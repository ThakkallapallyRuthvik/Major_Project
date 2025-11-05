import subprocess
import json
import os
from pydantic import BaseModel, Field
from typing import List, Dict

# --- Pydantic Schema for Structured Flaw Output ---
class FlawOutput(BaseModel):
    """Structured data model for a single SAST finding."""
    check_id: str = Field(description="The unique identifier for the Semgrep rule.")
    vulnerability_type: str = Field(description="The full CWE and a simplified vulnerability name.") # UPDATED DESCRIPTION
    file_path: str = Field(description="The path to the file containing the flaw.")
    line_number: int = Field(description="The starting line number of the flaw.")
    description: str = Field(description="A concise summary of the finding.")
    severity: str = Field(description="The severity level (e.g., 'High', 'Medium', 'Low').") # Clean Severity field

def run_and_parse_sast(target_dir: str, file_to_scan: str = None) -> str:
    """
    Executes the Semgrep scan on the target directory and parses the JSON output.
    Returns a JSON string containing a list of structured flaws or an error.
    """
    
    # Use a stable, core ruleset and scan only the temp file
    # We use 'p/python' as the most reliable default.
    semgrep_command = [
        "semgrep",
        "scan",
        "--config", "p/python",
        "--json",
        os.path.join(target_dir, file_to_scan) if file_to_scan else target_dir
    ]

    print(f"[Tool]: Running Semgrep scan on {target_dir}...")

    # Execute Semgrep using subprocess
    try:
        process = subprocess.run(
            semgrep_command,
            capture_output=True,
            text=True,
            check=False,  # Don't raise error on non-zero exit code (Semgrep returns 1 if findings are present)
            encoding='utf-8' # Ensure proper decoding of process output
        )
        
        # Semgrep outputs to stdout even if it finds vulnerabilities
        raw_output = process.stdout
        
        # If no findings are present, Semgrep's JSON output might be clean or empty.
        # However, if there are critical errors, they might be logged to stderr.
        if process.stderr and "error" in process.stderr.lower():
            print(f"[Tool]: Semgrep reported errors in stderr: {process.stderr.strip()}")
            # Attempt to parse output even with stderr errors, as sometimes findings are still present.
            if not raw_output:
                return json.dumps([{"error": f"Semgrep execution failed (Code {process.returncode}): {process.stderr.strip()}"}])
        
    except FileNotFoundError:
        return json.dumps([{"error": "Semgrep command not found. Ensure it is installed and in your PATH."}])
    except Exception as e:
        return json.dumps([{"error": f"Subprocess execution failed: {e}"}])

    # Parse the raw JSON output
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        print(f"[Tool]: Failed to decode Semgrep JSON. Raw Output:\n{raw_output[:500]}...")
        return json.dumps([{"error": "Failed to decode Semgrep JSON output. Check Semgrep installation."}])

    structured_flaws = []
    
    # Check for critical errors within the JSON report
    if data.get('errors'):
        error_messages = [e['message'] for e in data['errors']]
        if error_messages:
            return json.dumps([{"error": f"Semgrep reported internal errors: {'; '.join(error_messages)}"}])
            
    # Process successful findings
    for finding in data.get('results', []):
        metadata = finding.get('extra', {}).get('metadata', {})
        
        # NEW: Extract clean CWE ID and a simplified vulnerability name
        cwe_id = metadata.get('cwe', ['N/A'])[0]
        # Use a more user-friendly name derived from the check_id or a generic description
        vuln_name_parts = finding['check_id'].split('.')
        vulnerability_type_name = vuln_name_parts[-1].replace('_', ' ').title() if len(vuln_name_parts) > 1 else "Unknown Vulnerability"

        # Clean up description and context
        description_lines = finding['extra']['message'].split('\n')
        description = description_lines[0].strip() + ((" " + description_lines[1].strip()) if len(description_lines) > 1 else "")
        
        # Fix file path to be relative to the temporary root (which we ignore in the LLM prompt)
        clean_file_path = finding['path'].replace(os.path.sep, '/') 

        flaw = FlawOutput(
            check_id=finding['check_id'],
            # NEW: Combine for display, but keep severity separate
            vulnerability_type=f"{cwe_id}: {vulnerability_type_name}", 
            file_path=clean_file_path,
            line_number=finding['start']['line'],
            description=description.strip().replace('"', "'"),
            # NEW: Clean severity string
            severity=metadata.get('severity', 'UNKNOWN').title()
        )
        structured_flaws.append(flaw.model_dump())
        
    print(f"[Tool]: Successfully parsed {len(structured_flaws)} unique findings.")
    return json.dumps(structured_flaws)