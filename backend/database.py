from db import db
from sqlalchemy import text  # Import text for raw SQL
from datetime import datetime

def insert_user(username, password):
    sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    db.session.execute(sql, {"username": username, "password": password}) # Password not hashed
    db.session.commit()

def fetch_user_by_username(username):
    sql = f"SELECT * FROM users WHERE username = '{username}'"  # Direct string formatting
    result = db.session.execute(sql)  # SQL Injection vulnerability here
    return result.fetchone()

def insert_note(user_id, note_content):
    sql = text("INSERT INTO notes (user_id, note, created_at) VALUES (:user_id, :note, :created_at)")
    db.session.execute(sql, {"user_id": user_id, "note": note_content, "created_at": datetime.utcnow()})
    db.session.commit()

def fetch_notes_by_user_id(user_id):
    sql = text("SELECT id, note, created_at FROM notes WHERE user_id = :user_id")
    result = db.session.execute(sql, {"user_id": user_id})
    return result.fetchall()

def delete_note(note_id, user_id):
    sql = text("DELETE FROM notes WHERE id = :note_id AND user_id = :user_id")
    db.session.execute(sql, {"note_id": note_id, "user_id": user_id})
    db.session.commit()
