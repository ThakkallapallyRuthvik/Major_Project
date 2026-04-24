import sqlite3
import subprocess
import os
from flask import Flask, request, render_template_string, redirect, url_for, session

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
    """SECURE CODE: SQL Injection in Login fixed"""
    error = None
    if request.method == 'POST':
        # Import necessary modules inside the function body
        import sqlite3
        from flask import render_template_string, redirect, url_for, session, request

        # Get username and password from the form
        username = request.form['username']
        password = request.form['password']

        # Use parameterized query to prevent SQL Injection
        query = "SELECT * FROM users WHERE username = ? AND password = ?"

        # Connect to the database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            # Execute query with parameters
            c.execute(query, (username, password))
            user = c.fetchone()
            conn.close()

            # Check if the user exists
            if user:
                # Store the username in the session
                session['user'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid Credentials"
        except Exception as e:
            # Handle any exceptions
            error = str(e)

    # Simple Login Page HTML
    return render_template_string('''
        <html>
        <head><title>SysAdmin Login</title></head>
        <body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
            <h2>🔐 SysAdmin Portal</h2>
            <form method="post">
                <input type="text" name="username" placeholder="Username" required><br><br>
                <input type="password" name="password" placeholder="Password" required><br><br>
                <button type="submit">Login</button>
            </form>
            <p style="color: red">{{ error }}</p>
        </body>
        </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    return render_template_string(f'''
        <html>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1>👋 Welcome, {session['user']}</h1>
            <hr>
            
            <h3>🛠️ Tool 1: Network Health Check</h3>
            <form action="/ping" method="post">
                <label>Target IP:</label>
                <input type="text" name="ip" placeholder="8.8.8.8">
                <button type="submit">Ping Server</button>
            </form>
            
            <h3>🔎 Tool 2: Employee Search</h3>
            <form action="/search" method="get">
                <input type="text" name="q" placeholder="Search employee...">
                <button type="submit">Search</button>
            </form>
            
            <br><a href="/logout">Logout</a>
        </body>
        </html>
    ''')

@app.route('/ping', methods=['POST'])
def ping():
    import re
    import subprocess
    from flask import request, render_template_string

    ip = request.form.get('ip')

    # Validate user input using a regular expression
    if not re.match(r'^[a-zA-Z0-9.:]+$', ip):
        return render_template_string('<p>Invalid Input</p>')

    # Use subprocess with a list of arguments
    try:
        output = subprocess.check_output(['ping', '-c', '1', ip]).decode()
    except Exception as e:
        output = str(e)

    # Use render_template_string with named arguments to prevent XSS
    return render_template_string('<pre>{{ output }}</pre><br><a href="/dashboard">Back</a>', output=output)

@app.route('/search')
def search():
    from flask import render_template_string
    from shlex import quote
    query = request.args.get('q', '')

    import sqlite3
    import flask

    # --- 1. REAL LOGIC: Search the database ---
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # We use a SAFE query here (parameterized) so we don't accidentally 
    # trigger SQL Injection in the search bar. We want to focus on XSS here.
    c.execute("SELECT username FROM users WHERE username LIKE ?", ('%' + query + '%',))
    results = c.fetchall()
    conn.close()

    # --- 2. SECURE OUTPUT: Use render_template_string with named args ---
    template = """
    <h3>🔍 Search Results for: {{ query }}</h3>
    {% if results %}
    <ul>
    {% for user in results %}
    <li>found user: <b>{{ user[0] }}</b></li>
    {% endfor %}
    </ul>
    {% else %}
    <p>No users found.</p>
    {% endif %}
    <a href='/dashboard'>Back</a>
    """

    return render_template_string(template, query=query, results=results)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/debug')
def debug_route():
    import os
    import shlex
    import subprocess
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    if debug:
        cmd = shlex.quote("python") + " -m" + shlex.quote("pdb") + " app.py"
        subprocess.run(shlex.split(cmd))
    return 'Debug route'

if __name__ == '__main__':
    import os
    from flask import Flask, render_template_string
    app = Flask(__name__)
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    template = '''
    <html>
    <body>
    <h1>Debug Mode: {{ debug }}</h1>
    </body>
    </html>
    '''
    @app.route('/')
    def index():
        return render_template_string(template, debug=debug)
    app.run(debug=debug, port=5001)