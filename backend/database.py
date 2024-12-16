from db import db
from sqlalchemy import text  # Import text for raw SQL
from datetime import datetime

def insert_user(username, password):
    # Cryptographic Failure: The password is not hashed.
    sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    db.session.execute(sql, {"username": username, "password": password}) # Password not hashed
    db.session.commit()
    # HOW TO FIX
    # The password should be hashed before inserting into the database.
    # def insert_user(username, hashed_password):
    #     sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    #     db.session.execute(sql, {"username": username, "password": hashed_password})
    #     db.session.commit()

def fetch_user_by_username(username):
    # SQL Injection: User input is concatenated directly into the query
    sql = text(f"SELECT * FROM users WHERE username = '{username}'")
    result = db.session.execute(sql)
    return result.fetchone()
    # HOW TO FIX
    # Use parameterized queries to avoid SQL injection
    # def fetch_user_by_username(username):
    #     sql = text("SELECT * FROM users WHERE username = :username")
    #     result = db.session.execute(sql, {"username": username})
    #     return result.fetchone()

def insert_note(user_id, note_content):
    sql = text("INSERT INTO notes (user_id, note, created_at) VALUES (:user_id, :note, :created_at)")
    db.session.execute(sql, {"user_id": user_id, "note": note_content, "created_at": datetime.utcnow()})
    db.session.commit()

def fetch_notes_by_user_id(user_id):
    # Broken Access Control: Fetches all notes, ignoring user_id
    sql = text("SELECT id, note, created_at FROM notes")
    result = db.session.execute(sql)
    return result.fetchall()
    # HOW TO FIX
    # Fetch only the notes belonging to the logged-in user
    # def fetch_notes_by_user_id(user_id):
    #     sql = text("SELECT id, note, created_at FROM notes WHERE user_id = :user_id")
    #     result = db.session.execute(sql, {"user_id": user_id})
    #     return result.fetchall()

def delete_note(note_id, user_id):
    sql = text("DELETE FROM notes WHERE id = :note_id AND user_id = :user_id")
    db.session.execute(sql, {"note_id": note_id, "user_id": user_id})
    db.session.commit()
