# Cyber Security Base Project: Notes App

This is a vulnerable Flask-based note-taking web application built for educational purposes. It intentionally contains **five OWASP Top 10 vulnerabilities** from the **OWASP 2021 list**, along with their fixes (commented out in code). The application uses raw SQL queries through SQLAlchemy and stores data in a relational database.

---

## Notes App Features

- User sign-up and login
- Add and delete personal notes
- Demonstrates 5 of OWASP 2021 Top 10 flaws with fixes
- Backend using Flask + SQLAlchemy
- Frontend templating via Jinja2

---

## Vulnerabilities Demonstrated

| OWASP ID | Flaw                                |
|----------|-------------------------------------|
| A01      | Broken Access Control               |
| A02      | Cryptographic Failure               |
| A03      | Injection (SQL Injection)           |
| A05      | Security Misconfiguration (CSRF)    |
| A07      | Identification and Authentication Failures |

Fixes for all flaws are included in the code but **commented out**.

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone git@github.com:opturtio/Cyber-Security-Base-Project.git
cd Cyber-Security-Base-Project
```

### 2. Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4. Create a .env File
Generate and Add the Secret Key to the .env file:
```bash
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(64)}')" >> .env
```
Add Database URL to .env-file:
```bash
echo DATABASE_URL=sqlite:///your_db_name >> .env
```

### 5. Create a schema.sql File
Create schema file:
```bash
touch schema.sql
```
Then paste this into schema.sql:
```bash
DROP TABLE IF EXISTS notes CASCADE;
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
Create the Database:
```bash
psql -U postgres -d your_db_name < schema.sql
```

### 6. Create and Run init_db.py to Set Up Database
Create init_db.py:
```bash
touch init_db.py
```

Paste this inside:
```bash
from db import db
from sqlalchemy import text

def run_schema():
    with open("schema.sql") as f:
        schema_sql = f.read()
        for stmt in schema_sql.strip().split(";"):
            if stmt.strip():
                db.session.execute(text(stmt))
        db.session.commit()

if __name__ == "__main__":
    run_schema()
    print("Database initialized.")
```
Then run:
```bash
python init_db.py
```

### 7. Start the Application and Open browser
Start the app:
```bash
python app.py
```
Open your browser:
```bash
http://127.0.0.1:5000
```
