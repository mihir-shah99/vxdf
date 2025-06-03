"""
Sample vulnerable Flask application for testing VXDF source analysis.
"""
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search_users():
    """
    Vulnerable function with SQL injection.
    Line 14: Direct user input concatenation into SQL query.
    """
    query = request.args.get('q')  # User input source
    
    # VULNERABLE: Direct string concatenation - dangerous sink
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(sql)  # Dangerous operation
    results = cursor.fetchall()
    
    return f"Results: {results}"

if __name__ == '__main__':
    app.run(debug=True) 