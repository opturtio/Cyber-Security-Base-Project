# Cyber Security Base Project: Notes App

This is a vulnerable Flask-based note-taking web application built for educational purposes. It intentionally contains **five OWASP Top 10 vulnerabilities** from the **OWASP 2021 list**, along with their fixes (commented out in code). The application uses raw SQL queries through SQLAlchemy and stores data in a relational database. Vulnerabilities are demonstrated [here](/doc/Vulnerabilities.md).

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

**Prerequisite: PostgreSQL must be installed and running on your system.**

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

### 6. Create Database
Run this command to create the tables:
```bash
psql -U postgres -d your_db_name < schema.sql
```

### 7. Start the Application and Open browser
Start the app:
```bash
flask run
```
Open your browser:
```bash
http://127.0.0.1:5000
```
