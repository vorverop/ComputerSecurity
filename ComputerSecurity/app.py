from flask import Flask, request, jsonify, make_response, g, send_file
import bcrypt, json, os, time, secrets, html, re, logging
from functools import wraps
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)

# --------------------------
# Paths / Setup
# --------------------------
DATA_DIR = "data"
LOG_DIR = "logs"
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
FILES_FILE = os.path.join(DATA_DIR, "files.json")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")

for d in [DATA_DIR, LOG_DIR, UPLOAD_DIR]:
    os.makedirs(d, exist_ok=True)

# --------------------------
# Logging
# --------------------------
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "security.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_event(event, user, details, level="info"):
    entry = {
        "event": event,
        "user": user,
        "ip": request.remote_addr,
        "details": details
    }
    getattr(logging, level)(json.dumps(entry))

# --------------------------
# JSON Helpers
# --------------------------
def load_json(file):
    if not os.path.exists(file):
        return {}
    with open(file, "r") as f:
        return json.load(f)

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# --------------------------
# Encryption (Fernet)
# --------------------------
def get_cipher():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

cipher = get_cipher()

# --------------------------
# Validation
# --------------------------
def sanitize_input(s):
    return html.escape(s)

def valid_username(u):
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", u)

def valid_password(p):
    return (
            len(p) >= 12 and
            any(c.isupper() for c in p) and
            any(c.islower() for c in p) and
            any(c.isdigit() for c in p) and
            any(c in "!@#$%^&*" for c in p)
    )

# --------------------------
# Session Management
# --------------------------
def create_session(username):
    sessions = load_json(SESSIONS_FILE)
    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "username": username,
        "last_activity": time.time()
    }
    save_json(SESSIONS_FILE, sessions)
    return token

def get_current_user():
    token = request.cookies.get("session_token")
    sessions = load_json(SESSIONS_FILE)

    if token not in sessions:
        return None

    session = sessions[token]

    if time.time() - session["last_activity"] > 1800:
        del sessions[token]
        save_json(SESSIONS_FILE, sessions)
        return None

    session["last_activity"] = time.time()
    save_json(SESSIONS_FILE, sessions)
    return session["username"]

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper

# --------------------------
# RBAC
# --------------------------
def has_access(user, file_meta, action):
    role = load_json(USERS_FILE)[user]["role"]

    if role == "admin":
        return True

    if file_meta["owner"] == user:
        return True

    if user in file_meta.get("shared_with", {}):
        return action in file_meta["shared_with"][user]

    return False

# --------------------------
# Auth Routes
# --------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = sanitize_input(data.get("username", ""))
    password = data.get("password", "")

    if not valid_username(username):
        return jsonify({"error": "Invalid username"}), 400

    if not valid_password(password):
        return jsonify({"error": "Weak password"}), 400

    users = load_json(USERS_FILE)

    if username in users:
        return jsonify({"error": "User exists"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    users[username] = {
        "password": hashed.decode(),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": 0
    }

    save_json(USERS_FILE, users)
    log_event("REGISTER", username, {})
    return jsonify({"success": True})

# Rate limiting memory
login_attempts = {}

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = time.time()

    login_attempts.setdefault(ip, [])
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]

    if len(login_attempts[ip]) >= 10:
        return jsonify({"error": "Too many attempts"}), 429

    login_attempts[ip].append(now)

    data = request.json
    username = sanitize_input(data.get("username", ""))
    password = data.get("password", "")

    users = load_json(USERS_FILE)

    if username not in users:
        log_event("LOGIN_FAIL", username, {})
        return jsonify({"error": "Invalid"}), 401

    user = users[username]

    if time.time() < user["locked_until"]:
        return jsonify({"error": "Locked"}), 403

    if bcrypt.checkpw(password.encode(), user["password"].encode()):
        user["failed_attempts"] = 0
        token = create_session(username)

        resp = make_response(jsonify({"success": True}))
        resp.set_cookie("session_token", token,
                        httponly=True, secure=True,
                        samesite="Strict", max_age=1800)

        save_json(USERS_FILE, users)
        log_event("LOGIN_SUCCESS", username, {})
        return resp
    else:
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= 5:
            user["locked_until"] = time.time() + 900

        save_json(USERS_FILE, users)
        log_event("LOGIN_FAIL", username, {})
        return jsonify({"error": "Invalid"}), 401

# --------------------------
# File Upload (Encrypted)
# --------------------------
@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename)

    data = file.read()
    encrypted = cipher.encrypt(data)

    path = os.path.join(UPLOAD_DIR, filename + ".enc")
    with open(path, "wb") as f:
        f.write(encrypted)

    files = load_json(FILES_FILE)
    files[filename] = {
        "owner": g.user,
        "shared_with": {}
    }
    save_json(FILES_FILE, files)

    log_event("UPLOAD", g.user, {"file": filename})
    return jsonify({"success": True})

# --------------------------
# Download (Decrypt)
# --------------------------
@app.route("/download/<filename>")
@require_auth
def download(filename):
    filename = secure_filename(filename)

    files = load_json(FILES_FILE)

    if filename not in files:
        return jsonify({"error": "Not found"}), 404

    if not has_access(g.user, files[filename], "read"):
        log_event("ACCESS_DENIED", g.user, {"file": filename})
        return jsonify({"error": "Forbidden"}), 403

    path = os.path.join(UPLOAD_DIR, filename + ".enc")

    with open(path, "rb") as f:
        decrypted = cipher.decrypt(f.read())

    temp_path = os.path.join(UPLOAD_DIR, "temp_" + filename)
    with open(temp_path, "wb") as f:
        f.write(decrypted)

    log_event("DOWNLOAD", g.user, {"file": filename})
    return send_file(temp_path, as_attachment=True)



@app.route('/')
def home():
    return {"message": "Secure Document Sharing API is running"}


# --------------------------
# Share File
# --------------------------
@app.route("/share", methods=["POST"])
@require_auth
def share():
    data = request.json
    filename = secure_filename(data.get("filename"))
    target = data.get("user")
    permission = data.get("permission")  # read / write

    files = load_json(FILES_FILE)

    if filename not in files:
        return jsonify({"error": "Not found"}), 404

    if files[filename]["owner"] != g.user:
        return jsonify({"error": "Only owner can share"}), 403

    files[filename]["shared_with"].setdefault(target, [])
    files[filename]["shared_with"][target].append(permission)

    save_json(FILES_FILE, files)

    log_event("SHARE", g.user, {"file": filename, "target": target})
    return jsonify({"success": True})

# --------------------------
# Security Headers
# --------------------------
@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp

# --------------------------
# Run
# --------------------------
if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)
