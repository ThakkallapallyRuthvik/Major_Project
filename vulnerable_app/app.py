import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- Command Injection Vulnerability ---
@app.route('/ping', methods=['POST'])
def ping_server():
    """Allows user to ping an IP address."""
    target = request.form.get('target_ip')
    # VULNERABILITY: Directly concatenating user input into an OS command
    if target:
        command = f"ping -c 1 {target}" 
        result = os.popen(command).read()
        return f"<pre>{result}</pre>"
    return "Enter an IP to ping."

# --- Reflected XSS Vulnerability ---
@app.route('/search', methods=['GET'])
def search_page():
    """Simulates a search result page."""
    query = request.args.get('q', '')
    # VULNERABILITY: Directly rendering un-sanitized user input in the response
    if query:
        # Template is intentionally simple and vulnerable
        template = f"""
        <html><body>
        <p>Your search for: <strong>{query}</strong> returned no results.</p>
        </body></html>
        """
        return render_template_string(template)
    return "Search for something."

if __name__ == '__main__':
    # VULNERABILITY: Exposed on 0.0.0.0
    app.run(host='0.0.0.0', port=5000)
