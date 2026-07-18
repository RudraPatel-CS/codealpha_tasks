"""
Employee Portal - Sample Application (Audit Target)
-----------------------------------------------------
This is a deliberately vulnerable Flask application built for Internship
Task 3 (Secure Coding Review). It simulates a small internal HR/employee
portal with login, profile lookup, file download, and an admin utility.

DO NOT deploy this code. It exists only to be reviewed and fixed.
"""

import sqlite3
import os
import pickle
import hashlib
import subprocess

from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# --- VULN-01: Hardcoded secret key committed to source control ---
app.secret_key = "sk_live_9f8a7b6c5d4e3f2a1b0c"

DB_PATH = "employees.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY, name TEXT, salary INTEGER, ssn TEXT)""")
    conn.commit()
    conn.close()


# --- VULN-02: Weak password hashing (unsalted MD5) ---
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- VULN-03: SQL Injection via string formatting ---
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            hash_password(password),
        )
        conn = get_db()
        cur = conn.execute(query)
        user = cur.fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        return "Invalid credentials", 401

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/dashboard")
def dashboard():
    # --- VULN-04: Broken access control - no login check ---
    user_id = request.args.get("user_id", session.get("user_id"))
    conn = get_db()
    emp = conn.execute("SELECT * FROM employees WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    # --- VULN-05: Reflected XSS - unescaped user input rendered directly ---
    name = request.args.get("name", "")
    template = f"<h1>Welcome {name}</h1><p>Record: {dict(emp) if emp else 'N/A'}</p>"
    return render_template_string(template)


@app.route("/download")
def download():
    filename = request.args.get("file")
    # --- VULN-06: Path traversal - unsanitized filename joined to base dir ---
    path = os.path.join("uploads", filename)
    with open(path, "rb") as f:
        return f.read()


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # --- VULN-07: Command injection via shell=True with user input ---
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


@app.route("/import-profile", methods=["POST"])
def import_profile():
    # --- VULN-08: Insecure deserialization - pickle.loads on untrusted input ---
    data = request.get_data()
    profile = pickle.loads(data)
    return {"loaded": str(profile)}


@app.route("/admin/update-salary", methods=["POST"])
def update_salary():
    # --- VULN-09: No CSRF protection on a state-changing POST endpoint ---
    # --- VULN-04 (again): No check that session role == 'admin' ---
    emp_id = request.form["id"]
    new_salary = request.form["salary"]
    conn = get_db()
    conn.execute(f"UPDATE employees SET salary = {new_salary} WHERE id = {emp_id}")
    conn.commit()
    conn.close()
    return "Updated"


if __name__ == "__main__":
    init_db()
    # --- VULN-10: Debug mode enabled + bound to all interfaces in "prod" ---
    app.run(host="0.0.0.0", port=5000, debug=True)
