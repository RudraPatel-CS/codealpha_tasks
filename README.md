# Secure Coding Review — Employee Portal (Flask)

Internship Task 3: Secure Coding Review. This project contains a deliberately
vulnerable sample Flask application, a fully remediated version, and a formal
security review report.

⚠️ **`vulnerable/app.py` is intentionally insecure.** Run it only on
`localhost` for learning/demo purposes — never deploy it or expose it to a
network.

---

## Project structure

```
secure-review/
├── README.md
├── requirements.txt
├── Security_Review_Report.docx   # full write-up: findings, CWE/OWASP mapping, remediation
├── vulnerable/
│   └── app.py                    # audit target — 10 planted vulnerabilities
└── fixed/
    └── app.py                    # remediated version, fixes traceable by VULN-ID
```

---

## Requirements

- Python 3.9+
- pip

## Setup

1. Open this folder in VS Code (`File > Open Folder`).
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```
3. Activate it:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies used

| Package | Used for |
|---|---|
| `flask` | Web framework (both apps) |
| `werkzeug` | Secure password hashing (`fixed/app.py`) |
| `flask-wtf` | CSRF protection (`fixed/app.py`) |

Everything else imported (`sqlite3`, `os`, `pickle`, `hashlib`, `subprocess`,
`hmac`, `functools`, `ipaddress`) is part of Python's standard library — no
install needed.

---

## Running the vulnerable version

```bash
cd vulnerable
python app.py
```

Runs at `http://127.0.0.1:5000` (bound to `0.0.0.0`, debug mode on — this is
itself one of the findings, VULN-10). Explore routes like `/login`,
`/dashboard?user_id=1`, `/download?file=...`, `/ping?host=...` to see each
vulnerability described in the report.

## Running the fixed version

The fixed version requires a secret key to be set via environment variable
(no hardcoded secrets — see VULN-01 fix):

```bash
cd fixed
export FLASK_SECRET_KEY="some-random-dev-value"     # Windows: set FLASK_SECRET_KEY=some-random-dev-value
python app.py
```

Runs at `http://127.0.0.1:5000` only, debug off, CSRF-protected, with
parameterized queries and role-based access control.

> Note: the fixed app expects the same `users` / `employees` SQLite schema
> and an `uploads/` directory. These aren't auto-created in `fixed/app.py` —
> ask if you'd like a `setup_db.py` seed script added to make it runnable
> end-to-end out of the box.

---

## Summary of findings

Full detail is in `Security_Review_Report.docx`. Quick reference:

| ID | Finding | Severity |
|---|---|---|
| VULN-03 | SQL Injection (login) | Critical |
| VULN-07 | OS Command Injection (`/ping`) | Critical |
| VULN-08 | Insecure Deserialization (`pickle`) | Critical |
| VULN-04 | Broken Access Control / IDOR | Critical |
| VULN-01 | Hardcoded Secret Key | High |
| VULN-02 | Weak, Unsalted Password Hashing (MD5) | High |
| VULN-05 | Reflected XSS | High |
| VULN-06 | Path Traversal (`/download`) | High |
| VULN-09 | Missing CSRF Protection | Medium |
| VULN-10 | Debug Mode / Insecure Network Binding | Medium |

Each is documented with CWE ID, OWASP category, vulnerable code, impact,
and remediation, and each fix in `fixed/app.py` is comment-tagged with its
VULN-ID for traceability.

---

## VS Code extensions used

- **Python** (Microsoft) — language support, run/debug
- **Pylance** (Microsoft) — type checking, autocomplete
- *(optional)* **Bandit** or a Bandit CLI run — static security linting
- *(optional)* **SQLite Viewer** — inspect `employees.db`
