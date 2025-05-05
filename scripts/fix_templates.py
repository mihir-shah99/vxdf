#!/usr/bin/env python3
"""
Script to create or fix template and static directories.

This ensures that the Flask app can find templates and static files
regardless of how the application is run.
"""
import os
import shutil
from pathlib import Path

# Get the project root directory
ROOT_DIR = Path(__file__).resolve().parent.parent
ENGINE_DIR = ROOT_DIR / 'engine'
API_DIR = ROOT_DIR / 'api'

# Create template directory in engine if it doesn't exist
TEMPLATE_DIR = ENGINE_DIR / 'templates'
TEMPLATE_DIR.mkdir(exist_ok=True, parents=True)

# Create static directory in engine if it doesn't exist
STATIC_DIR = ENGINE_DIR / 'static'
STATIC_DIR.mkdir(exist_ok=True, parents=True)

# Create symlinks at the project root
for link_name, target_dir in [('templates', TEMPLATE_DIR), ('static', STATIC_DIR)]:
    link_path = ROOT_DIR / link_name
    
    # Remove existing symlink if it exists
    if link_path.is_symlink():
        os.unlink(link_path)
    
    # Create symlink
    os.symlink(target_dir, link_path, target_is_directory=True)
    print(f"Created symlink: {link_path} -> {target_dir}")

# Create basic index.html if it doesn't exist
INDEX_HTML = TEMPLATE_DIR / 'index.html'
if not INDEX_HTML.exists():
    with open(INDEX_HTML, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VXDF Validate</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="container">
        <h1>VXDF Validate</h1>
        <p>Welcome to VXDF Validate, a tool for validating vulnerability findings.</p>
        
        <div class="stats">
            <h2>Dashboard</h2>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <p class="stat-value">{{ total_findings }}</p>
            </div>
            <div class="stat-card">
                <h3>Validated Findings</h3>
                <p class="stat-value">{{ validated_findings }}</p>
            </div>
            <div class="stat-card">
                <h3>Exploitable Findings</h3>
                <p class="stat-value">{{ exploitable_findings }}</p>
            </div>
        </div>
        
        <h2>Upload a Finding</h2>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label for="file">Select a file:</label>
                <input type="file" name="file" id="file" required>
            </div>
            
            <div class="form-group">
                <label for="parser_type">Parser Type:</label>
                <select name="parser_type" id="parser_type">
                    <option value="sarif">SARIF</option>
                    <option value="json">JSON</option>
                    <option value="csv">CSV</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="validate">Validate Findings:</label>
                <input type="checkbox" name="validate" id="validate" value="true" checked>
            </div>
            
            <button type="submit" class="btn btn-primary">Upload</button>
        </form>
        
        {% if recent_findings %}
        <h2>Recent Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Exploitable</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in recent_findings %}
                <tr>
                    <td>{{ finding.name }}</td>
                    <td>{{ finding.vulnerability_type }}</td>
                    <td>{{ finding.severity }}</td>
                    <td>{{ "Yes" if finding.is_exploitable else "No" }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>
    
    <footer>
        <p>VXDF Validate v{{ version }} - &copy; 2023 Mihir Shah</p>
    </footer>
    
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>
</html>
""")
    print(f"Created basic index.html template at {INDEX_HTML}")

# Create basic CSS if it doesn't exist
CSS_DIR = STATIC_DIR / 'css'
CSS_DIR.mkdir(exist_ok=True, parents=True)

CSS_FILE = CSS_DIR / 'style.css'
if not CSS_FILE.exists():
    with open(CSS_FILE, 'w', encoding='utf-8') as f:
        f.write("""/* Basic styles for VXDF Validate */
body {
    font-family: Arial, sans-serif;
    line-height: 1.6;
    margin: 0;
    padding: 0;
    background-color: #f4f4f4;
}

.container {
    width: 80%;
    margin: 0 auto;
    padding: 20px;
}

h1 {
    color: #333;
    margin-bottom: 20px;
}

.stats {
    display: flex;
    flex-direction: column;
    margin-bottom: 30px;
}

.stat-card {
    background-color: #fff;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    padding: 15px;
    margin-bottom: 10px;
}

.stat-value {
    font-size: 1.5em;
    font-weight: bold;
}

.form-group {
    margin-bottom: 15px;
}

label {
    display: block;
    margin-bottom: 5px;
}

input[type="file"],
select {
    width: 100%;
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

button {
    display: inline-block;
    background-color: #4CAF50;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

button:hover {
    background-color: #45a049;
}

.findings-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

.findings-table th,
.findings-table td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

.findings-table th {
    background-color: #f2f2f2;
}

footer {
    text-align: center;
    margin-top: 50px;
    padding: 10px;
    background-color: #333;
    color: white;
}
""")
    print(f"Created basic CSS file at {CSS_FILE}")

# Create basic JavaScript if it doesn't exist
JS_DIR = STATIC_DIR / 'js'
JS_DIR.mkdir(exist_ok=True, parents=True)

JS_FILE = JS_DIR / 'main.js'
if not JS_FILE.exists():
    with open(JS_FILE, 'w', encoding='utf-8') as f:
        f.write("""// Main JavaScript for VXDF Validate
document.addEventListener('DOMContentLoaded', function() {
    console.log('VXDF Validate loaded');
    
    // Flash message handling
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.classList.add('fade-out');
            setTimeout(() => {
                message.remove();
            }, 500);
        }, 3000);
    });
});
""")
    print(f"Created basic JavaScript file at {JS_FILE}")

print("Template and static directories setup completed successfully!") 