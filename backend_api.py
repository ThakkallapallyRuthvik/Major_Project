import os
import json
import ast
import re
import sqlite3
from threading import Lock
from flask import Flask, request, jsonify, send_file, session, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from sast_tools import run_and_parse_sast
from ast_utils import extract_function_code, apply_patch_to_file

app = Flask(__name__)
CORS(app)
file_lock = Lock()

# --- SECURITY CONFIGURATION ---
app.secret_key = 'agentic_framework_secure_session_key'

# --- DATABASE SETUP ---
def init_framework_db():
    conn = sqlite3.connect('agent_framework.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS investigators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    occupation TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                 )''')
    conn.commit()
    conn.close()

init_framework_db()

# --- GROQ CONFIGURATION ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or "YOUR_API_KEY_HERE"
try:
    if "gsk_" not in GROQ_API_KEY:
        llm = None
    else:
        llm = ChatGroq(temperature=0.1, model_name="llama-3.3-70b-versatile", groq_api_key=GROQ_API_KEY)
except Exception:
    llm = None

# --- STRICT PROMPT ---
REMEDIATION_SYSTEM_PROMPT = (
    "You are an expert Secure Code Agent. Rewrite the function to be secure and Semgrep-compliant.\n"
    "CRITICAL RULES:\n"
    "1. COMMAND INJECTION (Ping/OS): You MUST use this exact pattern:\n"
    "   if not re.match(r'^[a-zA-Z0-9.:]+$', target_var):\n"
    "       return render_template_string('<p>Invalid Input</p>')\n"
    "   # Subprocess call happens ONLY HERE, after the return check\n"
    "   subprocess.check_output(['ping', '-c', '1', target_var])\n"
    "2. NO F-STRINGS FOR HTML: For XSS, ALWAYS use `render_template_string` with named arguments.\n"
    "3. APP CONFIG: If modifying `app.run`, ALWAYS set `use_reloader=False` and `debug=False`.\n"
    "4. SQL INJECTION: Use parameterized queries (e.g. `execute(query, (param,))`).\n"
    "5. IMPORTS: Put all imports (re, subprocess, render_template_string, sqlite3) INSIDE the function body."
)

def clean_llm_response(text):
    pattern = '`{3}(?:python)?\s*(.*?)`{3}'
    match = re.search(pattern, text, re.DOTALL)
    if match: return match.group(1).strip()
    return text.strip()

def fix_bad_imports(code_str):
    lines = code_str.split('\n')
    def_index = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('def '):
            def_index = i
            break
    if def_index == -1: return code_str
    
    new_lines = []
    moved_imports = []
    for i in range(def_index):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('import ') or stripped.startswith('from '):
            moved_imports.append(stripped)
        else:
            new_lines.append(line)
            
    new_lines.append(lines[def_index])
    indent = "    "
    for imp in moved_imports:
        new_lines.append(f"{indent}{imp}")
    new_lines.extend(lines[def_index+1:])
    return "\n".join(new_lines)

def validate_syntax(code_str):
    try:
        ast.parse(code_str)
        return True
    except SyntaxError:
        return False

# ==========================================
#         AUTHENTICATION ROUTES
# ==========================================
@app.route('/')
def index():
    if 'user' in session: return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET'])
def login_page(): return send_file('login.html')

@app.route('/register', methods=['GET'])
def register_page(): return send_file('register.html')

@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    if 'user' not in session: return redirect('/login')
    return send_file('dashboard.html')

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    hashed_password = generate_password_hash(data.get('password'))
    try:
        conn = sqlite3.connect('agent_framework.db')
        c = conn.cursor()
        c.execute("INSERT INTO investigators (username, email, occupation, password_hash) VALUES (?, ?, ?, ?)",
                  (data.get('username'), data.get('email'), data.get('occupation'), hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    conn = sqlite3.connect('agent_framework.db')
    c = conn.cursor()
    c.execute("SELECT * FROM investigators WHERE username = ?", (data.get('username'),))
    user = c.fetchone()
    conn.close()
    if user and check_password_hash(user[4], data.get('password')):
        session['user'] = user[1]
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.pop('user', None)
    return jsonify({"status": "success"})

@app.route('/api/auth/current_user', methods=['GET'])
def api_current_user():
    if 'user' in session: return jsonify({"username": session['user']})
    return jsonify({"error": "Not logged in"}), 401

# ==========================================
#         AGENTIC SCAN & FIX ROUTES
# ==========================================
@app.route('/api/scan', methods=['POST'])
def scan_directory():
    if 'user' not in session: return jsonify({"error": "Unauthorized"}), 401
    path = request.json.get('path')
    if not path or not os.path.exists(path): return jsonify({"error": "Invalid path"}), 400
    findings_json = run_and_parse_sast(path)
    return jsonify(json.loads(findings_json))

@app.route('/api/fix', methods=['POST'])
def fix_vulnerability():
    if 'user' not in session: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    file_path = data.get('file_path')
    line_number = data.get('line_number')
    
    with file_lock:
        # 1. EXTRACT THE FULL ORIGINAL FUNCTION
        func_name, original_func_code = extract_function_code(file_path, line_number)
        if not original_func_code: return jsonify({"status": "error", "message": "Function not found"}), 400

        messages = [
            SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
            HumanMessage(content=f"Fix {data.get('vulnerability_type')} in this code:\n\n{original_func_code}")
        ]
        try:
            response = llm.invoke(messages)
            cleaned_code = fix_bad_imports(clean_llm_response(response.content))

            if not validate_syntax(cleaned_code):
                return jsonify({"status": "error", "message": "AI syntax invalid"}), 500

            # 2. APPLY PATCH
            if apply_patch_to_file(file_path, func_name, cleaned_code):
                # 3. RETURN FULL ORIGINAL FUNCTION FOR SURGICAL ROLLBACK
                return jsonify({
                    "status": "success", 
                    "function": func_name, 
                    "new_code": cleaned_code,
                    "original_code": original_func_code 
                })
            return jsonify({"status": "error", "message": "File write failed"}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rollback', methods=['POST'])
def rollback_vulnerability():
    if 'user' not in session: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    
    with file_lock:
        # SURGICAL RESTORE: We use apply_patch_to_file to swap the NEW function with the ORIGINAL function!
        success = apply_patch_to_file(data.get('file_path'), data.get('func_name'), data.get('original_code'))
        if success:
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Rollback failed"}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=False)
