import bcrypt
import json
import time
import secrets
import re
import html
from functools import wraps
from flask import request, jsonify, make_response, g

# --------------------------
# Config / Files
# --------------------------
USERS_FILE = "data/users.json"
SESSIONS_FILE = "data/sessions.json"

SESSION_TIMEOUT = 1800  # 30 minutes
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes

RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10

# In-memory rate limiter
login_attempts = {}

# --------------------------
# JSON Helpers
# --------------------------
def load_json(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except:
        return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# --------------------------
# Validation
# --------------------------
def sanitize_input(s):
    return html.escape(s)

def valid_username(username):
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)

def valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

def valid_password(password):
    return (
            len(password) >= 12 and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*" for c in password)
    )

# --------------------------
# Session Management
# --------------------------
def create_session(username):
    sessions = load_json(SESSIONS_FILE)

    token = secrets.token_urlsafe(32)

    sessions[token] = {
        "username": username,
        "created_at": time.time(),
        "last_activity": time.time(),
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent")
    }

    save_json(SESSIONS_FILE, sessions)
    return token


def validate_session(token):
    sessions = load_json(SESSIONS_FILE)

    if token not in sessions:
        return None

    session = sessions[token]

    # Timeout check
    if time.time() - session["last_activity"] > SESSION_TIMEOUT:
        del sessions[token]
        save_json(SESSIONS_FILE, sessions)
        return None

    # Optional IP check (can break mobile users)
    # if session["ip"] != request.remote_addr:
    #     return None

    session["last_activity"] = time.time()
    sessions[token] = session
    save_json(SESSIONS_FILE, sessions)

    return session


def destroy_session(token):
    sessions = load_json(SESSIONS_FILE)
    if token in sessions:
        del sessions[token]
        save_json(SESSIONS_FILE, sessions)

# --------------------------
# Decorators
# --------------------------
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("session_token")
        session = validate_session(token) if token else None

        if not session:
            return jsonify({"error": "Unauthorized"}), 401

        g.user = session["username"]
        return f(*args, **kwargs)

    return wrapper


def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            users = load_json(USERS_FILE)
            user = g.get("user")

            if not user or user not in users:
                return jsonify({"error": "Unauthorized"}), 401

            if users[user]["role"] != role:
                return jsonify({"error": "Forbidden"}), 403

            return f(*args, **kwargs)

        return wrapper
    return decorator

# --------------------------
# Rate Limiting
# --------------------------
def check_rate_limit(ip):
    now = time.time()

    login_attempts.setdefault(ip, [])
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]

    if len(login_attempts[ip]) >= RATE_LIMIT_MAX:
        return False

    login_attempts[ip].append(now)
    return True

# --------------------------
# AUTH FUNCTIONS
# --------------------------
def register_user(data, logger=None):
    username = sanitize_input(data.get("username", ""))
    email = sanitize_input(data.get("email", ""))
    password = data.get("password", "")
    confirm = data.get("confirm", "")

    if not valid_username(username):
        return {"error": "Invalid username"}

    if not valid_email(email):
        return {"error": "Invalid email"}

    if not valid_password(password):
        return {"error": "Weak password"}

    if password != confirm:
        return {"error": "Passwords do not match"}

    users = load_json(USERS_FILE)

    # Check duplicates
    for u in users.values():
        if u.get("email") == email:
            return {"error": "Email already used"}

    if username in users:
        return {"error": "Username exists"}

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    users[username] = {
        "email": email,
        "password": hashed.decode(),
        "role": "user",
        "failed_attempts": 0,
        "locked_until": 0,
        "created_at": time.time()
    }

    save_json(USERS_FILE, users)

    if logger:
        logger("REGISTER", username, {})

    return {"success": True}


def login_user(data, logger=None):
    ip = request.remote_addr

    if not check_rate_limit(ip):
        return {"error": "Too many attempts"}, 429

    username = sanitize_input(data.get("username", ""))
    password = data.get("password", "")

    users = load_json(USERS_FILE)

    if username not in users:
        if logger:
            logger("LOGIN_FAIL", username, {})
        return {"error": "Invalid credentials"}, 401

    user = users[username]

    # Lockout check
    if time.time() < user.get("locked_until", 0):
        return {"error": "Account locked"}, 403

    if bcrypt.checkpw(password.encode(), user["password"].encode()):
        user["failed_attempts"] = 0

        token = create_session(username)

        resp = make_response({"success": True})
        resp.set_cookie(
            "session_token",
            token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=SESSION_TIMEOUT
        )

        save_json(USERS_FILE, users)

        if logger:
            logger("LOGIN_SUCCESS", username, {})

        return resp

    else:
        user["failed_attempts"] += 1

        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["locked_until"] = time.time() + LOCKOUT_TIME

        save_json(USERS_FILE, users)

        if logger:
            logger("LOGIN_FAIL", username, {})

        return {"error": "Invalid credentials"}, 401


def logout_user():
    token = request.cookies.get("session_token")

    if token:
        destroy_session(token)

    resp = make_response({"success": True})
    resp.delete_cookie("session_token")
    return resp
