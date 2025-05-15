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

This allows an attacker to enter a specially crafted input like ' OR 1=1 -- in the username field, which modifies the SQL logic to always return true. As a result, the attacker can bypass authentication without valid credentials. This vulnerability is demonstrated in [flaw1-sql-injection-A03-before-1](../doc/screenshots/flaw1-sql-injection-A03-before-1.png),  and the successful login bypass is shown in [flaw1-sql-injection-A03-before-2](../doc/screenshots/flaw1-sql-injection-A03-before-2.png).

**How to fix it:** Use parameterized queries instead of string interpolation:

```bash
sql = text("SELECT * FROM users WHERE username = :username")
db.session.execute(sql, {"username": username})
```

After the code is fixed, attempting the same SQL injection results in an “Invalid credentials” message, as shown in [flaw1-sql-injection-A03-after-1](../doc/screenshots/flaw1-sql-injection-A03-after-1.png). This confirms that the input is now correctly treated as data rather than executable SQL code.

### Flaw 2: CSRF Vulnerability (OWASP A05 – Security Misconfiguration)

**Location:** [templates/notes.html](/templates/notes.html#L9-L21), in the `form` for adding notes. [backend/routes.py](/backend/routes.py#L72-90), in the `/delete_user` route that handles the GET (normally POST) request.

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

**Location:** [backend/database.py](/backend/database.py#L37-L46), in the `fetch_notes_by_user_id` function.

**What’s wrong:** The function retrieves all notes from the database without filtering by user ID:

```bash
sql = text("SELECT id, note, created_at FROM notes")
```

In this scenario, one user writes a note, as shown in the [first screenshot](../doc/screenshots/flaw3-broken-access-control-A01-before-1.png). However, another user is able to view that note, as demonstrated in the [second image](../doc/screenshots/flaw3-broken-access-control-A01-before-2.png). This means both users [can see](./screenshots/flaw3-broken-access-control-A01-before-3.png) each other’s notes, regardless of ownership. Such behavior indicates a broken access control vulnerability, as users should only have access to their own data.

**How to fix it:** Filter notes by the currently logged-in user’s ID:

```bash
sql = text("SELECT id, note, created_at FROM notes WHERE user_id = :user_id")
```

Now, users can only view their own notes, as demonstrated in this [image](./screenshots/flaw3-broken-access-control-A01-after-1.png). This addresses a classic case of `insecure direct object reference`, one of the most common real-world issues in web apps.

### Flaw 4: Cryptographic Failure (OWASP A02 – Cryptographic Failures)

**Location:** [backend/database.py](/backend/database.py#L5-L15) in the `signup()` function and [backend/routes.py](/backend/database.py#L38-L45) in the `insert_user()` function.

**What’s wrong:** When a user creates an account, as shown in this [screenshot](./screenshots/flaw4-cryptographic-failure-A02-before-1.png), their password is stored in plaintext in the database, as seen in the following [image](./screenshots/flaw4-cryptographic-failure-A02-before-2.png). This is a critical security flaw. If an attacker gains access to the database, they can immediately read and misuse user credentials without any effort.

**How to fix it:** Use a strong one-way hashing function to hash passwords before storing them. Flask supports this via werkzeug.security.generate_password_hash.

Update the route logic to hash the password before calling `insert_user()`:
```bash
# routes.py
hashed_password = generate_password_hash(password)
insert_user(username, hashed_password)
```

No changes are needed to the `insert_user()` function itself if it already stores the password parameter. However, for clarity, password is renamed to hashed_password:
```bash
# database.py
def insert_user(username, hashed_password):
    sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
    db.session.execute(sql, {"username": username, "password": hashed_password})
    db.session.commit()
```

After applying the fix, passwords are no longer stored in plaintext. This is confirmed in [flaw4-cryptographic-failure-A02-after-1](./screenshots/flaw4-cryptographic-failure-A02-after-1.png), which shows the hashed password stored in the database. This protects user credentials even if the database is compromised.

### Flaw 5: Authentication Bypass (OWASP A07 – Identification and Authentication Failures)

**Location:** [backend/routes.py](/backend/routes.py#L17-L29), in the `login()` function.

**What’s wrong:** The login logic checks only whether a user with the submitted username exists, but does not verify the password at all. As a result, anyone who knows a valid username can log in without authentication.

```bash
if user:
    session["user_id"] = user.id
```

An attacker can gain access to any account simply by entering a valid username and adding any character as the password — without needing the correct credentials. As shown in this [screenshot](/doc/screenshots/flaw5-authentication-bypass-A07-before-1.png), the application does not verify the password at all, resulting in a complete authentication bypass.

**How to fix it:** Use check_password_hash to compare the submitted password with the stored hashed version in the database:

```bash
if user and check_password_hash(user.password, password):
    session["user_id"] = user.id
```

As shown in the [screenshot](/doc/screenshots/flaw5-authentication-bypass-A07-after-1.png), the user is now required to enter a valid password. If the credentials are incorrect, an “Invalid credentials” message is displayed, confirming that proper password verification is in place.


### Summary

This project demonstrates how five common web application vulnerabilities from the OWASP Top 10 (2021) can be introduced, and more importantly, how they can be effectively mitigated using secure coding practices in a minimal Flask application.  Each flaw is implemented in a functional context, such as login, note creation, or account management, and accompanied by a corresponding fix directly in the code. Before-and-after screenshots provide visual confirmation that the vulnerabilities are exploitable, and that the fixes successfully prevent abuse. All examples are based on small but common oversights: trusting user input, skipping validation, or omitting access controls. These subtle mistakes lead to serious risks like authentication bypass, SQL injection, or mass account deletion, all of which are explored and patched here. By walking through these flaws and their resolutions, the project not only strengthens the application but also builds developer awareness. Understanding how these issues arise, and how to fix them, is important for writing secure software in any environment.