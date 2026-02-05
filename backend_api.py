import os
import json
import ast
import re
from threading import Lock
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from sast_tools import run_and_parse_sast
from ast_utils import extract_function_code, apply_patch_to_file

app = Flask(__name__)
CORS(app)
file_lock = Lock()

# --- CONFIGURATION ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or "API_KEY"

try:
    if "gsk_" not in GROQ_API_KEY:
        print("⚠️ Warning: No Groq Key found.")
        llm = None
    else:
        llm = ChatGroq(temperature=0.1, model_name="llama-3.3-70b-versatile", groq_api_key=GROQ_API_KEY)
except:
    llm = None

# --- FINAL STRICT PROMPT ---
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
    match = re.search(r'```(?:python)?\s*(.*?)```', text, re.DOTALL)
    if match: return match.group(1).strip()
    return text.strip()

def fix_bad_imports(code_str):
    """Moves imports from outside the function to inside."""
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
    except SyntaxError as e:
        print(f"❌ SYNTAX ERROR: {e}")
        return False

@app.route('/api/scan', methods=['POST'])
def scan_directory():
    path = request.json.get('path')
    if not path or not os.path.exists(path): return jsonify({"error": "Invalid path"}), 400
    findings_json = run_and_parse_sast(path)
    return jsonify(json.loads(findings_json))

@app.route('/api/fix', methods=['POST'])
def fix_vulnerability():
    data = request.json
    file_path = data.get('file_path')
    line_number = data.get('line_number')
    vuln_type = data.get('vulnerability_type')
    
    with file_lock:
        func_name, func_code = extract_function_code(file_path, line_number)
        
        if not func_code:
            return jsonify({"status": "error", "message": "Function not found"}), 400

        print(f"🔧 Fixing {vuln_type} in {func_name}...")
        
        messages = [
            SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
            HumanMessage(content=f"Fix {vuln_type} in this code:\n\n{func_code}")
        ]
        
        try:
            response = llm.invoke(messages)
            cleaned_code = clean_llm_response(response.content)
            cleaned_code = fix_bad_imports(cleaned_code)

            print(f"--- AI CODE FOR {func_name} ---")
            print(cleaned_code)
            print("-------------------------------")

            if not validate_syntax(cleaned_code):
                return jsonify({"status": "error", "message": "AI generated invalid syntax"}), 500

            success = apply_patch_to_file(file_path, func_name, cleaned_code)
            
            if success:
                return jsonify({"status": "success", "function": func_name})
            else:
                return jsonify({"status": "error", "message": "File write failed"}), 500

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/')
def serve_dashboard():
    # This serves the HTML file directly, mimicking a production server
    return send_file('dashboard.html')

if __name__ == '__main__':
    app.run(port=5000, debug=False)
