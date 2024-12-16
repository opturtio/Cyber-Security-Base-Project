1. SQL Injection Vulnerability
**Location:** [backend/database.py](/backend/database.py#L10-L13), inside the fetch_user_by_username function.

**Why It’s Vulnerable:** The user input username is directly concatenated into the SQL string, allowing an attacker to manipulate the query structure.


2. XSS Vulnerability
**Location:** [templates/notes.html](/templates/notes.html#L10-L13), when rendering user-provided notes.

**Why It’s Vulnerable:** The |safe filter disables Jinja2’s auto-escaping, meaning user input could contain malicious HTML or JavaScript.


3. CSRF Vulnerability
**Location:** [templates/notes.html](/templates/notes.html#L4-L7), inside the form that adds notes.

**Why It’s Vulnerable:** The form does not include a CSRF token, so it can be exploited using a forged POST request from another website.


4. Broken Access Control
**Location:** [backend/database.py](/backend/database.py#L24-L28), in fetch_notes_by_user_id.

**Why It’s Vulnerable:**
No User Verification: Fetches all notes without verifying ownership.

5. Cryptographic Failure
**Location:** []() [backend/database.py](/backend/database.py#L5-L8), inside the insert_user function.

**Why It’s Vulnerable:** The password is not hashed. Instead of using generate_password_hash from Werkzeug, it is assumed that the password is hashed but pass it as plaintext. This leads to storing plain passwords.