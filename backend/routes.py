from flask import render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from backend.database import insert_user, fetch_user_by_username, insert_note, fetch_notes_by_user_id, delete_note

def configure_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("notes"))

        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            user = fetch_user_by_username(username)
            if user and check_password_hash(user.password, password):
                session["user_id"] = user.id
                session["username"] = user.username
                return redirect(url_for("notes"))
            return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            hashed_password = generate_password_hash(password)
            insert_user(username, hashed_password)
            return redirect(url_for("login"))
        return render_template("signup.html")

    @app.route("/notes", methods=["GET", "POST"])
    def notes():
        if "user_id" not in session:
            return redirect(url_for("login"))
        
        user_id = session["user_id"]
        notes = fetch_notes_by_user_id(user_id)
        
        if request.method == "POST":
            note_content = request.form["note"]
            insert_note(user_id, note_content)
            return redirect(url_for("notes"))
        
        return render_template("notes.html", notes=notes)

    @app.route("/delete/<int:note_id>")
    def delete(note_id):
        # Delete the note without checking if the note belongs to the current user
        delete_note(note_id)  # No user validation, deletes any note by ID
        return redirect(url_for("notes"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

# Attach routes to the app
from app import app
configure_routes(app)
