/**
 * ⚠️  INTENTIONALLY VULNERABLE APP — FOR EDUCATIONAL PURPOSES ONLY ⚠️
 * Mirrors the Python/Flask vulnerable demo, written in Node.js + Express.
 *
 * Vulnerabilities included:
 *  1. SQL Injection       — /login
 *  2. OS Command Injection — /ping
 *  3. Reflected XSS       — /search
 *  4. Path Traversal      — /file
 *  5. Hardcoded Secret    — session middleware
 *  6. Stored XSS          — /dashboard (username echoed raw)
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const app = express();

// Define a function to handle user input
function handleUserInput(input) {
    // Import required modules inside the function body
    const ejs = require('ejs');

    // Validate user input to prevent XSS attacks
    if (typeof input !== 'string' || input.length === 0) {
        return 'Invalid input';
    }

    try {
        // Use a template engine to render the HTML page
        const template = ejs.compile('Hello, <%= name %>!');
        const html = template({ name: input });

        // Return the rendered HTML
        return html;
    } catch (error) {
        // Handle any errors that may occur during execution
        return `An error occurred: ${error.message}`;
    }
}

// Example usage:
const userInput = 'John Doe';
const result = handleUserInput(userInput);
console.log(result);

// Define a route to handle user input
app.get('/greeting', (req, res) => {
    const name = req.query.name;

    // Validate and sanitize user input
    if (!name || typeof name !== 'string') {
        res.status(400).send('Invalid input');
        return;
    }

    // Use the validated input to generate the HTML page
    const html = handleUserInput(name);

    // Send the rendered HTML as the response
    res.send(html);
});

// Start the server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});
const db = new sqlite3.Database(':memory:');

// --- MIDDLEWARE ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'super_secret_key',   // ❌ FLAW 5: Hardcoded, weak session secret
    resave: false,
    saveUninitialized: true,
}));

// --- DATABASE SETUP ---
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
    db.run("INSERT INTO users (username, password) VALUES ('admin', 'admin')");
    db.run("INSERT INTO users (username, password) VALUES ('guest', 'guest')");
    db.run("INSERT INTO users (username, password) VALUES ('alice', 'alice123')");
});

// --- AUTH GUARD ---
const requireLogin = (req, res, next) => {
    if (!req.session.user) return res.redirect('/');
    next();
};

// ---------------------------------------------------------------
// ROUTE 1: GET / — Login Page
// ---------------------------------------------------------------

// Create a new file named index.ejs in the views directory
// with the following content:
// 
// <html>
//   <head>
//     <title>SysAdmin Login</title>
//   </head>
//   <body style="font-family:sans-serif;text-align:center;margin-top:50px">
//     <h2>🔐 SysAdmin Portal</h2>
//     <form method="POST" action="/login">
//       <input type="text"     name="username" placeholder="Username" required/><br/><br/>
//       <input type="password" name="password" placeholder="Password" required/><br/><br/>
//       <button type="submit">Login</button>
//     </form>
//     <p style="color:red"><%= error %></p>
//   </body>
// </html>

// ---------------------------------------------------------------
// ROUTE 2: POST /login — SQL Injection
// ---------------------------------------------------------------
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // ❌ FLAW 1: String interpolation into SQL → SQL Injection
    // Exploit: username = admin'--
    // Query becomes: SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, user) => {
        if (err) return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
        if (user) {
            req.session.user = user.username;
            return res.redirect('/dashboard');
        }
        res.redirect('/?error=Invalid+Credentials');
    });
});

// ---------------------------------------------------------------
// ROUTE 3: GET /dashboard — Stored XSS
// ---------------------------------------------------------------
app.get('/dashboard', requireLogin, (req, res) => {
    // ❌ FLAW 6: session.user echoed into HTML with no sanitization → Stored XSS
    // If an attacker registers as <script>alert(1)</script>, it executes here
    res.send(`
    <html><body style="font-family:sans-serif;padding:20px">
      <h1>👋 Welcome, ${req.session.user}</h1>
      <hr/>

      <h3>🛠️ Tool 1: Network Health Check</h3>
      <form method="POST" action="/ping">
        <input type="text" name="ip" placeholder="8.8.8.8"/>
        <button type="submit">Ping Server</button>
      </form>

      <h3>🔎 Tool 2: Employee Search</h3>
      <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search employee..."/>
        <button type="submit">Search</button>
      </form>

      <h3>📂 Tool 3: File Viewer</h3>
      <form method="GET" action="/file">
        <input type="text" name="name" placeholder="report.txt"/>
        <button type="submit">Read File</button>
      </form>

      <br/><a href="/logout">Logout</a>
    </body></html>
  `);
});

// ---------------------------------------------------------------
// ROUTE 4: POST /ping — OS Command Injection
// ---------------------------------------------------------------
app.post('/ping', requireLogin, (req, res) => {
    const ip = req.body.ip;

    // ❌ FLAW 2: User input concatenated directly into shell command
    // Exploit (Linux):   8.8.8.8; whoami
    // Exploit (Windows): 8.8.8.8 & whoami
    const cmd = process.platform === 'win32'
        ? `ping -n 1 ${ip}`
        : `ping -c 1 ${ip}`;

    exec(cmd, (err, stdout, stderr) => {
        const output = stdout || stderr || String(err);
        res.send(`<pre>${output}</pre><a href="/dashboard">Back</a>`);
    });
});

// ---------------------------------------------------------------
// ROUTE 5: GET /search — Reflected XSS
// ---------------------------------------------------------------

app.get('/search', requireLogin, (req, res) => {
    const q = req.query.q || '';

    // Safe parameterized query — SQL injection NOT the focus here
    db.all("SELECT username FROM users WHERE username LIKE ?", [`%${q}%`], (err, rows) => {
        // Create a template with named arguments
        const template = `
            <h3>🔍 Results for: {{ query | safe }}</h3>
            {% if error %}
                <p style="color:red">{{ error | safe }}</p>
            {% elif results %}
                <ul>
                    {% for result in results %}
                        <li><b>{{ result.username | safe }}</b></li>
                    {% endfor %}
                </ul>
            {% else %}
                <p>No users found.</p>
            {% endif %}
            <a href="/dashboard">Back</a>
        `;

        // Render the template with the query and results
        const data = {
            query: q,
            error: err ? err.message : null,
            results: rows
        };

        // Use a template engine like Nunjucks to render the template
        const nunjucks = require('nunjucks');
        nunjucks.configure({ autoescape: true });
        const html = nunjucks.renderString(template, data);

        res.send(html);
    });
});

// ---------------------------------------------------------------
// ROUTE 6: GET /file — Path Traversal
// ---------------------------------------------------------------

app.get('/file', requireLogin, (req, res) => {
    const filename = req.query.name || '';

    // Sanitize the filename using path.basename()
    const sanitizedFilename = path.basename(filename);

    // Join the sanitized filename with the base directory path
    const filePath = path.join(__dirname, 'files', sanitizedFilename);

    // Check if the file exists and is within the expected directory
    if (!filePath.startsWith(path.join(__dirname, 'files'))) {
        return res.send(`<p style="color:red">Error: Invalid file path</p><a href="/dashboard">Back</a>`);
    }

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.send(`<p style="color:red">Error: ${err.message}</p><a href="/dashboard">Back</a>`);
        res.send(`<pre>${data}</pre><a href="/dashboard">Back</a>`);
    });
});

// ---------------------------------------------------------------
// ROUTE 7: GET /logout
// ---------------------------------------------------------------
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- START ---
app.listen(5001, () => {
    console.log('⚠️  Vulnerable app running at http://localhost:5001');
});