import sqlite3
import subprocess
import os
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# --- DATABASE SETUP (Runs once on start) ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin')")
    c.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest')")
    conn.commit()
    conn.close()

init_db()

# --- VULNERABLE ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def login():
    """VULNERABILITY: SQL Injection in Login"""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # ❌ FLAW: Direct string concatenation allows SQL Injection
        # Exploit: Enter "admin' --" as username to bypass password
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            
            if user:
                session['user'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid Credentials"
        except Exception as e:
            error = str(e)
            
    # Simple Login Page HTML
    return render_template("login.html", error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    return render_template("dashboard.html", user=session['user'])

@app.route('/ping', methods=['POST'])
def ping():
    """VULNERABILITY: OS Command Injection"""
    ip = request.form.get('ip')
    
    # ❌ FLAW: Passing user input directly to shell
    # Exploit: Enter "8.8.8.8; start calc" (Windows) or "8.8.8.8; ls" (Linux)
    command = f"ping -n 1 {ip}" if os.name == 'nt' else f"ping -c 1 {ip}"
    
    try:
        # shell=True is the root cause of the vulnerability
        output = subprocess.check_output(command, shell=True).decode()
    except Exception as e:
        output = str(e)
        
    return f"<pre>{output}</pre><br><a href='/dashboard'>Back</a>"

@app.route('/search')
def search():
    """VULNERABILITY: Reflected XSS (but with real DB logic)"""
    query = request.args.get('q', '')
    
    # --- 1. REAL LOGIC: Search the database ---
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # We use a SAFE query here (parameterized) so we don't accidentally 
    # trigger SQL Injection in the search bar. We want to focus on XSS here.
    c.execute("SELECT username FROM users WHERE username LIKE ?", ('%' + query + '%',))
    results = c.fetchall()
    conn.close()
    
    # --- 2. VULNERABLE OUTPUT: Reflected XSS ---
    # The vulnerability is here: f"Results for: {query}"
    # If the user types <script>..., it gets echoed back raw.
    html_response = f"<h3>🔍 Search Results for: {query}</h3>"
    
    if results:
        html_response += "<ul>"
        for user in results:
            html_response += f"<li>found user: <b>{user[0]}</b></li>"
        html_response += "</ul>"
    else:
        html_response += "<p>No users found.</p>"
        
    html_response += "<a href='/dashboard'>Back</a>"
    
    return html_response

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001,use_reloader=False)