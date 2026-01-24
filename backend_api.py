import os
import json
import ast
from flask import Flask, request, jsonify
from flask_cors import CORS
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from sast_tools import run_and_parse_sast
from ast_utils import extract_function_code, apply_patch_to_file

app = Flask(__name__)
CORS(app) 

# --- CONFIGURATION ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or "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"

try:
    if "gsk_" not in GROQ_API_KEY:
        print("⚠️ Warning: No Groq Key found.")
        llm = None
    else:
        llm = ChatGroq(temperature=0, model_name="llama-3.3-70b-versatile", groq_api_key=GROQ_API_KEY)
except:
    llm = None

# --- STRICT PROMPT ---
REMEDIATION_SYSTEM_PROMPT = (
    "You are an expert Secure Code Agent. You fix vulnerabilities in Python code. "
    "Input: A vulnerable Python function. "
    "Output: ONLY the corrected Python function code. "
    "Rules: "
    "1. STRUCTURE: The output must follow this EXACT structure:\n"
    "   @decorator\n"
    "   def function_name(args):\n"
    "       import ... (ALL imports must be indented here)\n"
    "       ... (logic)\n"
    "2. CRITICAL: NEVER place imports between the decorator and the def."
    "3. SECURITY: Use 'shlex.quote' for subprocess and 'render_template_string' with named args."
    "4. Do NOT output any text before or after the code."
)

def forceful_import_fixer(code_str):
    """
    A dumb-but-reliable text processor that forces imports inside the function.
    It doesn't care about regex patterns. It iterates line by line.
    """
    # 1. Clean Markdown wrappers
    clean_code = code_str.strip()
    if "```python" in clean_code:
        clean_code = clean_code.split("```python")[1].split("```")[0].strip()
    elif "```" in clean_code:
        clean_code = clean_code.split("```")[1].split("```")[0].strip()

    lines = clean_code.split('\n')
    final_lines = []
    pending_imports = []
    
    # We assume the imports we want to move are strictly *before* the 'def' line
    # and *after* any decorators.
    found_def = False
    
    for line in lines:
        stripped = line.strip()
        
        # If we hit the function definition, we are crossing the boundary
        if stripped.startswith('def ') and stripped.endswith(':'):
            found_def = True
            final_lines.append(line)
            # DUMP all captured imports right here, indented by 4 spaces
            for imp in pending_imports:
                # Ensure we don't double-indent if the LLM was weird
                clean_imp = imp.lstrip() 
                final_lines.append(f"    {clean_imp}") 
            pending_imports = [] # Clear them
            continue
            
        # If we haven't found 'def' yet, check if this line is an import
        if not found_def:
            if stripped.startswith('import ') or stripped.startswith('from '):
                # Capture it to move it later
                pending_imports.append(line)
                continue
        
        # Otherwise, just keep the line (decorators, comments, or body code)
        final_lines.append(line)
        
    return "\n".join(final_lines)

def validate_syntax(code_str):
    """
    Tries to compile the code. If it fails, returns False.
    This PREVENTS file corruption.
    """
    try:
        ast.parse(code_str)
        return True
    except SyntaxError as e:
        print(f"❌ SYNTAX VALIDATION FAILED: {e}")
        return False

@app.route('/api/scan', methods=['POST'])
def scan_directory():
    path = request.json.get('path')
    if not path or not os.path.exists(path): return jsonify({"error": "Invalid path"}), 400
    
    # Run scan
    findings_json = run_and_parse_sast(path)
    
    # SAFETY CHECK: If Semgrep failed to parse the file (returned 0 results instantly on a known bad file),
    # we should alert the user.
    if "syntax error" in findings_json.lower():
         return jsonify({"error": "CRITICAL: app.py contains Syntax Errors. Please restore the backup."}), 500
         
    return jsonify(json.loads(findings_json))

@app.route('/api/fix', methods=['POST'])
def fix_vulnerability():
    data = request.json
    file_path = data.get('file_path')
    line_number = data.get('line_number')
    vuln_type = data.get('vulnerability_type')
    
    # 1. Extract Code
    func_name, func_code = extract_function_code(file_path, line_number)
    
    if not func_code:
        return jsonify({"status": "error", "message": "Function not found (File might be corrupted)"}), 400

    print(f"Fixing {func_name}...")
    
    messages = [
        SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
        HumanMessage(content=f"Fix {vuln_type} in:\n{func_code}")
    ]
    
    try:
        response = llm.invoke(messages)
        
        # 1. Force Move Imports (Text Surgery)
        cleaned_code = forceful_import_fixer(response.content)
        
        # 2. VALIDATE SYNTAX (The Safety Valve)
        if not validate_syntax(cleaned_code):
            print(f"❌ Bad AI Code for {func_name}:\n{cleaned_code}")
            return jsonify({"status": "error", "message": "AI generated invalid syntax. Aborting save."}), 500

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
    # 3. Apply Patch
    success = apply_patch_to_file(file_path, func_name, cleaned_code)
    
    if success:
        return jsonify({"status": "success", "function": func_name})
    else:
        return jsonify({"status": "error", "message": "File write failed"}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=False)