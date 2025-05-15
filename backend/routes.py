from flask import render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from backend.database import insert_user, fetch_user_by_username, insert_note, fetch_notes_by_user_id, delete_note, delete_user_by_id
import secrets

def configure_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("notes"))

        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            user = fetch_user_by_username(username)

            # OWASP A07: Identification and Authentication Failures
            # Authentication Bypass:
            # This allows any user to log in with just a valid username, without verifying the password.
            if user:
                session["user_id"] = user.id
                session["username"] = user.username
                return redirect(url_for("notes"))
            # HOW TO FIX:
            # Always verify the password securely using check_password_hash
            # if user and check_password_hash(user.password, password):
            #     session["user_id"] = user.id
            #     session["username"] = user.username
            #     return redirect(url_for("notes"))

            return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            
            # OWASP A02: Cryptographic Failures
            # Password is stored in plaintext instead of being hashed.
            insert_user(username, password)
            # HOW TO FIX:
            # Hash the password before calling insert_user
            # hashed_password = generate_password_hash(password)
            # insert_user(username, hashed_password)
            
            return redirect(url_for("login"))
        return render_template("signup.html")

    @app.route("/notes", methods=["GET", "POST"])
    def notes():
        if "user_id" not in session:
            return redirect(url_for("login"))

        user_id = session["user_id"]
        username = session.get("username", "Guest")
        notes = fetch_notes_by_user_id(user_id)

        if request.method == "POST":
            note_content = request.form["note"]
            insert_note(user_id, note_content)
            return redirect(url_for("notes"))

        return render_template("notes.html", notes=notes, greeting=f"Hello, {username}")

    @app.route("/delete/<int:note_id>")
    def delete(note_id):
        if "user_id" not in session:
            return redirect(url_for("login"))

        user_id = session["user_id"]
        delete_note(note_id, user_id)
        return redirect(url_for("notes"))

    @app.route("/delete_user/<int:user_id>", methods=["GET"])
    def delete_user(user_id):
        # OWASP A05: Security Misconfiguration
        # CSRF Vulnerability – This route allows deletion of any user without CSRF protection or authentication.
        delete_user_by_id(user_id)
        return f"User {user_id} deleted"
    # HOW TO FIX:
    # Use POST and validate CSRF token
    # @app.route("/delete_user/<int:user_id>", methods=["POST"])
    # def delete_user(user_id):
    #     if "user_id" not in session or session["user_id"] != user_id:
    #         return "Unauthorized", 403
    #
    #     token = request.form.get("csrf_token")
    #     if not token or token != session.get("csrf_token"):
    #         return "Invalid CSRF token", 400
    #
    #     delete_user_by_id(user_id)
    #     session.clear()
    
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))