import os
import json
import tempfile
import shutil
from flask import Flask, request, jsonify
from pydantic import BaseModel, Field
from typing import List, Dict
from langchain_community.chat_models import ChatOllama
from langchain.prompts import SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate
from werkzeug.utils import secure_filename
from sast_tools import run_and_parse_sast, FlawOutput

app = Flask(__name__)

# --- LLM SETUP (Attacker Agent Persona) ---
try:
    llm = ChatOllama(model="llama3", temperature=0.5)
    print("✅ Ollama (llama3) connection initialized for API server.")
except Exception as e:
    print(f"❌ ERROR: Failed to initialize ChatOllama. Ensure Ollama is running and 'llama3' is pulled. Error: {e}")
    llm = None 

# --- LLM Prompt Template ---
ATTACKER_SYSTEM_PROMPT = (
    "You are a specialized SECURITY TESTER Agent working in a simulated, academic environment. "
    "Your sole purpose is to generate the NECESSARY MALICIOUS INPUT STRING to trigger the flaw found by the static analysis engine. "
    "The output of this string will be used by the Defender Agent's test harness to validate the vulnerability, NOT to perform a real attack. "
    "Constraints: "
    "1. For OS Command Injection (CWE-78), generate the single input string that executes 'whoami' using a metacharacter (e.g., '127.0.0.1 && whoami')."
    "2. For XSS (CWE-79), generate the single raw input string that, when reflected, executes the JavaScript command: alert('VULN_TEST'). **This must be the raw string, including all HTML/script tags.**"
    "3. You MUST output ONLY the raw exploit string, with absolutely no preamble, explanation, markdown formatting (e.g., ```), or quotes surrounding the exploit."
    "4. If you cannot generate the exploit or hit a safety guardrail, you MUST output the exact phrase: 'LLM_REFUSED_PAYLOAD'"
)

ATTACKER_HUMAN_PROMPT = (
    "Analyze this structural flaw (JSON format) and generate the exploit string:\n"
    "---FLAW DETAILS---\n"
    "{flaw_details_json}"
)

# --- API ENDPOINT ---
@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    if not request.json or 'code' not in request.json:
        return jsonify({"error": "Missing 'code' in request body."}), 400

    code_to_analyze = request.json['code']
    results = []

    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, "temp_app.py")
        
        with open(temp_file_path, 'w') as f:
            f.write(code_to_analyze)

        # 1. Run SAST Scan (Symbolic Analysis)
        print(f"[API] Running SAST scan on {temp_file_path}...")
        structured_findings_json = run_and_parse_sast(temp_dir, file_to_scan="temp_app.py")
        
        try:
            findings_list = json.loads(structured_findings_json)
        except json.JSONDecodeError:
            return jsonify({"error": "Failed to parse SAST output."}), 500

        if not findings_list or ("error" in findings_list[0] if isinstance(findings_list[0], dict) else False):
            return jsonify({"error": findings_list[0].get("error", "No flaws found or critical SAST error occurred.")}), 200

        # --- DEDUPLICATION LOGIC (Based on CWE ID + Line Number) ---
        unique_findings = {}
        for finding in findings_list:
            # Safely extract the CWE ID (e.g., 'CWE-79')
            try:
                cwe_id = finding['vulnerability_type'].split(':')[0].strip()
            except IndexError:
                cwe_id = finding['check_id'] 

            # Create a unique key using the CWE ID and the line number
            key = (cwe_id, finding['line_number'])
            
            if key not in unique_findings:
                unique_findings[key] = finding
                
        deduplicated_findings_list = list(unique_findings.values())
        print(f"[API] Filtered {len(findings_list) - len(deduplicated_findings_list)} duplicate findings. Processing {len(deduplicated_findings_list)} unique flaws.")
        # --- END DEDUPLICATION LOGIC ---

        # 2. Iterate through UNIQUE flaws and run LLM Reasoning
        for flaw_dict in deduplicated_findings_list:
            flaw = FlawOutput(**flaw_dict)
            
            # Skip configuration flaws for exploit generation
            if "CWE-668" in flaw.vulnerability_type:
                exploit_payload = "N/A (Configuration Flaw)"
            else:
                if llm is None:
                    exploit_payload = "LLM UNAVAILABLE: Cannot generate exploit."
                else:
                    print(f"[API] -> LLM Generating exploit for: {flaw.vulnerability_type} at {flaw.file_path}:{flaw.line_number}...")

                    chat_template = ChatPromptTemplate.from_messages([
                        SystemMessagePromptTemplate.from_template(ATTACKER_SYSTEM_PROMPT),
                        HumanMessagePromptTemplate.from_template(ATTACKER_HUMAN_PROMPT)
                    ])

                    flaw_details_for_llm = json.dumps(flaw.model_dump(), indent=2)
                    final_prompt_value = chat_template.format_messages(flaw_details_json=flaw_details_for_llm)
                    
                    response = llm.invoke(final_prompt_value)
                    exploit_payload = response.content.strip()
            
                    # --- NEW: POST-PROCESSING CLEANUP AND FILTERING ---
                    # 1. Strip common LLM markdown wrappers and language tags
                    if exploit_payload.startswith('```') and exploit_payload.endswith('```'):
                        exploit_payload = exploit_payload.strip('`').strip()
                        if exploit_payload.startswith(('html', 'bash', 'python')):
                            exploit_payload = exploit_payload.split('\n', 1)[-1].strip()

                    # 2. Strip the unwanted preamble text (like the one you observed)
                    preamble_prefix = "I can generate the exploit string for you. Here's the OS Command Injection (CWE-78) exploit string:"
                    if exploit_payload.startswith(preamble_prefix):
                        exploit_payload = exploit_payload.replace(preamble_prefix, "").strip()

                    # 3. Check for explicit or implicit refusals (as requested)
                    if "LLM_REFUSED_PAYLOAD" in exploit_payload:
                        exploit_payload = "N/A (LLM Refusal)"
                    elif "I cannot" in exploit_payload or "Is there something else I can help you with" in exploit_payload or "cannot provide an input string" in exploit_payload:
                        exploit_payload = "N/A (LLM Refusal/Safety Guardrail)"
                    # --- END POST-PROCESSING ---
                    
            results.append({
                "id": flaw.check_id,
                "type": flaw.vulnerability_type, 
                "severity": flaw.severity,
                "context": f"{flaw.file_path}:{flaw.line_number}",
                "exploit": exploit_payload,
                "description": flaw.description.strip(),
            })

    except Exception as e:
        print(f"CRITICAL ERROR in API: {e}")
        return jsonify({"error": f"Internal server error during processing: {e}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            
    return jsonify({"results": results})

if __name__ == '__main__':
    @app.after_request
    def add_cors_headers(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        return response
        
    print("Starting Attacker Agent API...")
    app.run(host='127.0.0.1', port=8000, debug=False)