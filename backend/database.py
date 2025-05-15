from db import db
from sqlalchemy import text
from datetime import datetime

def insert_user(username, password):
    # OWASP A02: Cryptographic Failure
    # Flaw 4: Cryptographic Failure - The password is stored in plaintext. It should be hashed before saving.
    sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    db.session.execute(sql, {"username": username, "password": password})
    # HOW TO FIX:
    # Hash the password before inserting into the database
    # def insert_user(username, hashed_password):
    #     sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    #     db.session.execute(sql, {"username": username, "password": hashed_password})
    db.session.commit()

def fetch_user_by_username(username):
    # OWASP A03: Injection
    # Flaw 1: SQL Injection - User input is concatenated directly into SQL query, which allows SQL injection.
    sql = text(f"SELECT * FROM users WHERE username = '{username}'")
    result = db.session.execute(sql)
    # HOW TO FIX:
    # Use parameterized queries to prevent SQL injection
    # sql = text("SELECT * FROM users WHERE username = :username")
    # result = db.session.execute(sql, {"username": username})
    return result.fetchone()

def insert_note(user_id, note_content):
    sql = text("INSERT INTO notes (user_id, note, created_at) VALUES (:user_id, :note, :created_at)")
    db.session.execute(sql, {
        "user_id": user_id,
        "note": note_content,
        "created_at": datetime.now().replace(microsecond=0)
    })
    db.session.commit()

def fetch_notes_by_user_id(user_id):
    # OWASP A01: Broken Access Control
    # Flaw 3: Broken Access Control - This function fetches all notes without restricting to the user's own notes.
    sql = text("SELECT id, note, created_at FROM notes")
    result = db.session.execute(sql)
    # HOW TO FIX:
    # Limit returned notes to only those owned by the logged-in user
    # sql = text("SELECT id, note, created_at FROM notes WHERE user_id = :user_id")
    # result = db.session.execute(sql, {"user_id": user_id})
    return result.fetchall()

def delete_note(note_id, user_id):
    sql = text("DELETE FROM notes WHERE id = :note_id AND user_id = :user_id")
    db.session.execute(sql, {"note_id": note_id, "user_id": user_id})
    db.session.commit()
    
def delete_user_by_id(user_id):
    # OWASP A05: Security Misconfiguration
    # Flaw 2: CSRF Vulnerability – This function allows deleting any user without authentication or CSRF protection.
    sql = text("DELETE FROM users WHERE id = :id")
    db.session.execute(sql, {"id": user_id})
    db.session.commit()
    # HOW TO FIX:
    # Only allow the authenticated user to delete their own account (check session in route)
    # AND use CSRF protection to prevent forged requests.