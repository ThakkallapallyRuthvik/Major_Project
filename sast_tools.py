import subprocess
import json
import os
from pydantic import BaseModel

class FlawOutput(BaseModel):
    check_id: str
    vulnerability_type: str
    file_path: str
    line_number: int
    description: str
    severity: str
    code_snippet: str

def run_and_parse_sast(target_directory: str, language: str) -> str:
    print(f"[Scanner] Starting analysis on: {target_directory}")
    
    semgrep_command = [
        "semgrep", "scan",
        "--config", f"p/{language}",
        "--json",
        target_directory
    ]

    try:
        process = subprocess.run(
            semgrep_command,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
    except FileNotFoundError:
        return json.dumps([{"error": "Semgrep not found."}])

    try:
        data = json.loads(process.stdout)
        # print("semgrep output data:",data['results'][0]['extras']['metadata']['technology'])
    except json.JSONDecodeError:
        return json.dumps([{"error": "Failed to parse Semgrep output."}])

    # --- INTELLIGENT GROUPING ---
    # We group by (File + Line Number). 
    # If a line has multiple bugs, we combine them into one 'Super-Finding'.
    grouped_findings = {}

    for finding in data.get('results', []):
        abs_path = finding['path']
        if not os.path.isabs(abs_path):
             abs_path = os.path.join(target_directory, finding['path'])
             
        line_no = finding['start']['line']
        key = (abs_path, line_no)
        
        metadata = finding.get('extra', {}).get('metadata', {})
        cwe = metadata.get('cwe', ['Unknown'])[0]
        msg = finding['extra']['message'].split('\n')[0]

        if key not in grouped_findings:
            # First time seeing this line
            snippet = ""
            try:
                with open(abs_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    start_line = line_no - 1
                    snippet = "".join(lines[max(0, start_line): min(len(lines), start_line + 3)])
            except:
                snippet = "Error reading file."

            grouped_findings[key] = {
                "check_id": finding['check_id'],
                "vulnerability_type": f"{cwe}",
                "file_path": abs_path,
                "line_number": line_no,
                "description": msg, # Start with first error message
                "severity": metadata.get('severity', 'MEDIUM'),
                "code_snippet": snippet,
                "count": 1
            }
        else:
            # We already have a bug on this line. Just append the type.
            existing = grouped_findings[key]
            if cwe not in existing['vulnerability_type']:
                existing['vulnerability_type'] += f", {cwe}"
                existing['description'] += f" | {msg}"
            existing['count'] += 1

    # Convert dict back to list
    final_results = []
    for val in grouped_findings.values():
        final_results.append(val)

    # Sort: File Path (A-Z) -> Line Number (High to Low)
    # This ensures we fix bottom-up, preventing line shifts.
    final_results.sort(key=lambda x: (x['file_path'], x['line_number']), reverse=True)

    print(f"[Scanner] Reduced to {len(final_results)} unique fixable locations.")
    return json.dumps(final_results)