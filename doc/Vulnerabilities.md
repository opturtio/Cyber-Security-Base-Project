# Project Report: Web Application Vulnerabilities & Fixes

**Repository link:** [Cyber-Security-Base-Project](https://github.com/opturtio/Cyber-Security-Base-Project)

This project is a deliberately vulnerable Flask-based notes application built to demonstrate five real vulnerabilities from the OWASP Top 10 (2021). The goal was to not only implement these flaws but also provide working fixes that are commented out in the code. Screenshots demonstrating the before/after states are stored in the [doc/screenshots/](../doc/screenshots/) directory.

The application includes user login, note creation and deletion, and a PostgreSQL-backed database. Below are the five vulnerabilities I implemented, why they are serious, where they occur in the codebase, and how they can be resolved.

### Flaw 1: SQL Injection (OWASP A03 – Injection)

**Location:** [backend/database.py](/backend/database.py#L17-L26), in the `fetch_user_by_username` function.

**What’s wrong:** The login logic builds a SQL query by directly injecting the username input into the SQL string:

```bash
sql = text(f"SELECT * FROM users WHERE username = '{username}'")
```

This means a user can log in using inputs like ' OR 1=1 -- , which tricks the SQL engine into always returning true. That allows bypassing authentication completely. 

**How to fix it:** Use parameterized queries instead of string interpolation:

```bash
sql = text("SELECT * FROM users WHERE username = :username")
db.session.execute(sql, {"username": username})
```

This ensures that user input is treated as data, not SQL code. 

### Flaw 2: CSRF Vulnerability (OWASP A05 – Security Misconfiguration)

**Location:** [templates/notes.html](/templates/notes.html#L9-L22), in the form for adding notes. [backend/routes](../backend/routes.py#L76-94), in the `/delete_user` route that handles the GET (normally POST) request.

**What’s wrong:** The GET route for deleting a user (/delete_user/<int:user_id>) is exposed without requiring any authentication or CSRF protection. This means anyone, including unauthenticated attackers, can craft a malicious HTML page that silently sends deletion requests to the server using image tags. As a result, an attacker can mass-delete users without ever being logged in or having any valid session.

In this case, an attacker can upload malicious [html-file](../doc/csrf_attack_file.html) on other tab [flaw2-csrf-vulnerability-A05-before-1](../doc/screenshots/flaw2-csrf-vulnerability-A05-before-1.png) and run it. In this case the malicious program asks which indexes to delete starting from one [flaw2-csrf-vulnerability-A05-before-2](../doc/screenshots/flaw2-csrf-vulnerability-A05-before-2.png). The program will delete all the indexes between 1 and the given index. Here we can see the proof that indexes between 1 and 11 have been deleted [flaw2-csrf-vulnerability-A05-before-3](../doc/screenshots/flaw2-csrf-vulnerability-A05-before-3.png).

**How to fix it:** Use POST instead of GET for destructive actions:

```bash
@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
```

Require authentication:

```bash
if "user_id" not in session or session["user_id"] != user_id:
    return "Unauthorized", 403
```

Generate and validate a CSRF token:

```bash
if "csrf_token" not in session:
    session["csrf_token"] = secrets.token_hex(16)
```

Inject CSRF token in the form:
```bash
<form method="POST" action="/delete_user/{{ user_id }}">
  <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
  <button type="submit">Delete Account</button>
</form>
```

Validate the token server-side:
```bash
token = request.form.get("csrf_token")
if not token or token != session.get("csrf_token"):
    return "Invalid CSRF token", 400
```
This time  when the attacker uploads the malicious [html-file](../doc/screenshots/flaw2-csrf-vulnerability-A05-after-1.png) and attempts to delete user indexes from 1 to 15, the application successfully prevents the action. This confirms that the CSRF vulnerability has been mitigated. The result can be verified in the [database screenshot](../doc/screenshots/flaw2-csrf-vulnerability-A05-after-2.png), which shows that no unauthorized deletions occurred.
This protection ensures that only legitimate, user-initiated requests can delete an account. Attackers cannot forge such requests unless they can guess the CSRF token, which is virtually impossible. Additionally, since POST requests from external origins cannot be automatically triggered by images, links, or simple HTML elements like <img> or <a>, using the POST method significantly reduces the risk of CSRF attacks.

### Flaw 3: Broken Access Control (OWASP A01 – Broken Access Control)

**Location:** [backend/database.py](/backend/database.py#L37-L46), in the fetch_notes_by_user_id function.

**What’s wrong:** The function retrieves all notes from the database without filtering by user ID:

```bash
sql = text("SELECT id, note, created_at FROM notes")
```

This means any user can see notes that don't belong to them — a clear violation of access control principles.

**How to fix it:** Filter notes by the currently logged-in user’s ID:

```bash
sql = text("SELECT id, note, created_at FROM notes WHERE user_id = :user_id")
```

This is a classic case of "insecure direct object reference," and is one of the most common real-world issues in web apps.

### Flaw 4: Cryptographic Failure (OWASP A02 – Cryptographic Failures)

**Location:** [backend/database.py](/backend/database.py#L5-L8) and routes.py

**What’s wrong:** Passwords are stored in plaintext in the database. This is a critical mistake. If an attacker gains access to the database, they can immediately use the credentials.

**How to fix it:** Hash passwords using a strong algorithm like bcrypt. Flask provides a convenient wrapper via werkzeug.security.generate_password_hash.

In signup():

```bash
hashed_password = generate_password_hash(password)
insert_user(username, hashed_password)
```

And later, during login, passwords should be verified with check_password_hash. This ensures that even if the database is breached, the credentials remain safe.

### Flaw 5: Authentication Bypass (OWASP A07 – Identification and Authentication Failures)

**Location:** routes.py, in the login() function.

**What’s wrong:** The login route checks if a user with the given username exists — but never verifies the password. That means anyone can log in as any user if they just know the username.

```bash
if user:
    session["user_id"] = user.id
```

No password checking at all. Total bypass.

**How to fix it:** Use check_password_hash to compare the submitted password with the stored hashed version:

```bash
if user and check_password_hash(user.password, password):
    session["user_id"] = user.id
```

This fix is written and commented in the code. Once uncommented, the login system behaves securely.

### Summary

All flaws are implemented realistically and fixable using industry best practices. The application uses no external frameworks like Django, so the responsibility for these protections is left to the developer — as it often is in real-world minimal Flask apps.

Screenshots showing each flaw and its fix in action are available in the repository under the screenshots/ folder, named accordingly (flaw-1-before.png, flaw-1-after.png, etc.).

The project demonstrates how small oversights — like skipping a WHERE clause, or forgetting to hash a password — can lead to major security problems. Fixing them doesn't just improve the app, it makes the developer more security-aware, which is exactly the point of this exercise.