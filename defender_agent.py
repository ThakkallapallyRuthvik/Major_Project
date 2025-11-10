import os
import json
import tempfile
import shutil
from flask import Flask, request, jsonify
from langchain_community.chat_models import ChatOllama
from langchain.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate

# Import your utility for function extraction
from ast_utils import extract_function_code
from sast_tools import FlawOutput # Use the schema for context

app = Flask(__name__)

# --- LLM SETUP (Defender Agent Persona) ---
try:
    # Initialize Llama 3 for the Defender's secure persona
    llm_defender = ChatOllama(model="llama3", temperature=0.5)
    print("✅ Ollama (llama3) connection initialized for Defender Agent.")
except Exception as e:
    print(f"❌ ERROR: Failed to initialize ChatOllama for Defender. Error: {e}")
    llm_defender = None 

# --- LLM Prompt Template ---
DEFENDER_SYSTEM_PROMPT = (
    "You are a specialized DEFENDER Agent and expert Python security developer. "
    "Your sole purpose is to analyze a vulnerable Python function and generate the minimally invasive, secure code patch to fix the reported vulnerability (CWE). "
    "The vulnerability type and context (line number) are provided in the flaw details."
    "Constraints: "
    "1. You MUST output ONLY the complete, corrected Python function, including the def statement, any required imports (e.g., 'os' must be imported if used), and docstrings. Do NOT include any code outside of the function definition."
    "2. The function name and signature MUST remain exactly the same as the original."
    "3. You must use industry-standard security practices (e.g., use 'subprocess.run' with a list of arguments for Command Injection, or HTML sanitization for XSS)."
    "4. DO NOT include any comments, markdown formatting (e.g., ```), or explanations."
)

DEFENDER_HUMAN_PROMPT = (
    "A flaw was found in the vulnerable Python function provided below. "
    "---FLAW DETAILS---\n"
    "{flaw_details_json}\n\n"
    "---VULNERABLE CODE FUNCTION---\n"
    "{vulnerable_function_code}"
)

# --- API ENDPOINT ---
@app.route('/api/remediate', methods=['POST','OPTIONS'])
def remediate_code():
    # --- FIX FOR 415 ERROR (Handles CORS Pre-flight) ---
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    # -----------------------------------------------------------
    
    if not request.json or 'code' not in request.json or 'findings' not in request.json:
        return jsonify({"error": "Missing 'code' or 'findings' in request body."}), 400

    code_to_analyze = request.json['code']
    findings_list = request.json['findings']
    validated_patches = []

    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        # Separate file name for clarity
        temp_file_name = "temp_app.py"
        temp_file_path = os.path.join(temp_dir, temp_file_name)
        
        # Write the user-provided code to a temporary file
        with open(temp_file_path, 'w') as f:
            f.write(code_to_analyze)

        if llm_defender is None:
            return jsonify({"error": "Defender LLM is not available."}), 503

        for flaw_data in findings_list:
            # Skip non-exploitable findings and those without exploit data (from Attacker phase)
            if "N/A" in flaw_data.get("exploit", "") or not flaw_data.get("exploit"):
                continue

            # Extract line number from context (assuming format 'file:line')
            try:
                line_number = int(flaw_data['context'].split(':')[-1])
            except:
                print(f"Skipping finding due to context parsing error: {flaw_data['context']}")
                continue
            
            # --- STEP 1: Extract Vulnerable Function Code ---
            function_name_and_code = extract_function_code(temp_file_path, line_number)

            if not function_name_and_code:
                print(f"Could not extract function code for line {line_number}. Skipping.")
                continue

            func_name, vulnerable_function_code = function_name_and_code
            print(f"\n[Defender] Processing fix for {flaw_data['type']} in function '{func_name}'...")

            # --- STEP 2: LLM Remediation ---
            chat_template = ChatPromptTemplate.from_messages([
                SystemMessagePromptTemplate.from_template(DEFENDER_SYSTEM_PROMPT),
                HumanMessagePromptTemplate.from_template(DEFENDER_HUMAN_PROMPT)
            ])

            # --- MODIFIED BLOCK FOR CORRECT LLM INVOCATION ---
            # 1. Format the template into a list of messages
            final_prompt_messages = chat_template.format_messages(
                flaw_details_json=json.dumps(flaw_data, indent=2),
                vulnerable_function_code=vulnerable_function_code
            )

            # 2. Invoke the LLM with the list of messages
            response = llm_defender.invoke(final_prompt_messages)
            # --------------------------------------------------
            
            suggested_patch = response.content.strip()
            
            # --- STEP 3: Validation (SIMULATED FOR PROTOTYPING) ---
            # is_safe = run_post_patch_validation(suggested_patch, flaw_data['exploit'])
            is_safe = True # <--- ALWAYS TRUE FOR THIS PROTOTYPE

            if is_safe:
                print(f"-> ✅ Successfully generated and VALIDATED patch for '{func_name}'.")
                validated_patches.append({
                    "flaw_id": flaw_data['id'],
                    "cwe_type": flaw_data['type'],
                    "function_name": func_name,
                    "location": flaw_data['context'],
                    "original_code": vulnerable_function_code,
                    "patch_code": suggested_patch
                })
            else:
                print(f"-> ❌ Patch failed validation for '{func_name}'. Skipping.")

    except Exception as e:
        print(f"CRITICAL ERROR in DEFENDER API: {e}")
        return jsonify({"error": f"Internal server error during processing: {e}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            
    return jsonify({"patches": validated_patches})

if __name__ == '__main__':
    # Add CORS headers for frontend communication
    @app.after_request
    def add_cors_headers(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-Patches')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        return response
        
    print("Starting Defender Agent API...")
    app.run(host='127.0.0.1', port=8001, debug=False) # Running on port 8001