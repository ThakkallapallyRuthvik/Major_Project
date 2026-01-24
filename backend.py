import os
import json
import re  # <--- NEW: For parsing code blocks
from flask import Flask, request, jsonify
from flask_cors import CORS
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from sast_tools import run_and_parse_sast
from ast_utils import extract_function_code, apply_patch_to_file

app = Flask(__name__)
CORS(app) 

# --- CONFIGURATION (Local Only) ---
try:
    llm = ChatOllama(model="llama3", temperature=0.2) 
    print("✅ Unified Agent: Connected to Ollama (Llama 3)")
except Exception as e:
    print(f"❌ Error: Ollama not reachable. {e}")
    llm = None

# --- IMPROVED PROMPT ---
REMEDIATION_SYSTEM_PROMPT = (
    "You are an expert Secure Code Agent. You fix vulnerabilities in Python code. "
    "Input: A vulnerable Python function and a vulnerability description. "
    "Output: ONLY the corrected Python function code. "
    "Rules: "
    "1. Keep the same function name and arguments."
    "2. CRITICAL: If you use new modules (like 'sqlite3', 'subprocess'), IMPORT THEM INSIDE THE FUNCTION."
    "   Example: def login(): import sqlite3; ..."
    "3. NEVER use f-strings (f'...') to construct HTML or SQL queries."
    "4. ALWAYS use 'render_template_string' with named arguments."
    "5. Do NOT output any text before or after the code. No 'Here is the fix'."
)

@app.route('/api/scan', methods=['POST'])
def scan_directory():
    path = request.json.get('path')
    if not path or not os.path.exists(path):
        return jsonify({"error": "Invalid directory path"}), 400
    
    print(f"Scanning {path}...")
    findings_json = run_and_parse_sast(path)
    return jsonify(json.loads(findings_json))

@app.route('/api/fix', methods=['POST'])
def fix_vulnerability():
    data = request.json
    file_path = data.get('file_path')
    line_number = data.get('line_number')
    vuln_type = data.get('vulnerability_type')
    
    if not llm:
        return jsonify({"status": "error", "message": "LLM Offline"}), 500

    func_name, func_code = extract_function_code(file_path, line_number)
    
    if not func_code:
        return jsonify({"status": "error", "message": "Could not isolate function/block."}), 400

    print(f"Fixing {vuln_type} in {func_name}...")
    
    messages = [
        SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
        HumanMessage(content=f"Fix {vuln_type} in this code:\n{func_code}")
    ]
    
    try:
        response = llm.invoke(messages)
        raw_content = response.content.strip()
        
        # --- ROBUST EXTRACTION LOGIC (The Fix) ---
        # 1. Try to find code between ```python and ```
        match = re.search(r"```python(.*?)```", raw_content, re.DOTALL)
        if match:
            patched_code = match.group(1).strip()
        else:
            # 2. Try just ``` and ```
            match = re.search(r"```(.*?)```", raw_content, re.DOTALL)
            if match:
                patched_code = match.group(1).strip()
            else:
                # 3. Fallback: Use the whole string
                patched_code = raw_content

    except Exception as e:
        return jsonify({"status": "error", "message": f"LLM Generation Failed: {str(e)}"}), 500
    
    success = apply_patch_to_file(file_path, func_name, patched_code)
    
    if success:
        return jsonify({
            "status": "success", 
            "function": func_name,
            "original": func_code,
            "patched": patched_code
        })
    else:
        return jsonify({"status": "error", "message": "Failed to write file."}), 500

if __name__ == '__main__':
    # CRITICAL: use_reloader=False prevents restart loop
    app.run(port=5000, debug=False)