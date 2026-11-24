
import os
import sqlite3
import subprocess
import ipaddress
import secrets
import shutil

from pathlib import Path
from flask import Flask, request, g, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

DB = "/tmp/week04.db"

# Store uploads outside any publicly accessible directory.
UPLOAD_DIR = Path("/tmp/week04_private_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Maximum upload size: 5 MB.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

FLAG_SQLI = os.environ.get("FLAG_SQLI", "FLAG{sqli_demo}")
FLAG_CMDI = os.environ.get("FLAG_CMDI", "FLAG{cmdi_demo}")

# Restrict accepted file extensions.
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def seed():
    con = sqlite3.connect(DB)

    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    # Initialize only if the database is empty.
    count = con.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    if count == 0:
        con.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [
                ("alice", "alicepw"),
                ("bob", "bobpw"),
                ("admin", FLAG_SQLI)
            ]
        )

    con.commit()
    con.close()


@app.route("/")
def index():
    return (
        "Week 4 — Injection lab (SECURED)\n"
        "Endpoints:\n"
        "  /login?user=&pw=\n"
        "  /search?q=\n"
        "  /ping?host=\n"
        "  /upload\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


# --------------------------------------------------
# SQL INJECTION FIX (CWE-89)
# --------------------------------------------------

@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pw", "")

    # Parameterized query prevents SQL injection.
    q = """
        SELECT id, username
        FROM users
        WHERE username = ? AND password = ?
    """

    row = db().execute(q, (user, pw)).fetchone()

    if row:
        return "Welcome %s\n" % row[1]

    return "Login failed\n", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")

    # Escape LIKE wildcard characters.
    term = (
        term.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
    )

    # Parameterized LIKE query.
    q = """
        SELECT id, username
        FROM users
        WHERE username LIKE ? ESCAPE '\\'
    """

    rows = db().execute(q, ("%" + term + "%",)).fetchall()

    return "\n".join(
        "%s:%s" % (r[0], r[1]) for r in rows
    ) + "\n"


# --------------------------------------------------
# COMMAND INJECTION FIX (CWE-78)
# --------------------------------------------------

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    try:
        # Accept only valid IPv4 or IPv6 addresses.
        address = ipaddress.ip_address(host)

    except ValueError:
        return "Invalid IP address\n", 400

    # Never pass user input through a shell.
    ping_executable = shutil.which("ping")

    if not ping_executable:
        return "Ping utility unavailable\n", 503

    command = [
        ping_executable,
        "-c", "1",
        str(address)
    ]

    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )

        return (
            "<pre>%s</pre>" %
            (result.stdout + result.stderr)
        )

    except subprocess.TimeoutExpired:
        return "Ping timed out\n", 504


# --------------------------------------------------
# UNRESTRICTED FILE UPLOAD FIX (CWE-434)
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="f" required>
            <input type="submit">
        </form>
        '''

    if "f" not in request.files:
        return "Missing file\n", 400

    f = request.files["f"]

    if not f.filename:
        return "No file selected\n", 400

    # Sanitize filename.
    filename = secure_filename(f.filename)

    if not filename or "." not in filename:
        return "Invalid filename\n", 400

    extension = filename.rsplit(".", 1)[1].lower()

    # Extension allowlist.
    if extension not in ALLOWED_EXTENSIONS:
        return "File type not allowed\n", 400

    # Generate a random filename to prevent path traversal
    # and filename collisions.
    random_filename = secrets.token_hex(16) + "." + extension

    dest = UPLOAD_DIR / random_filename

    try:
        f.save(dest)

    except OSError:
        return "File upload failed\n", 500

    # Never expose a filesystem path.
    return "File uploaded successfully\n", 201


# --------------------------------------------------
# APPLICATION STARTUP
# --------------------------------------------------

if __name__ == "__main__":
    seed()

    # Debug mode disabled.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

