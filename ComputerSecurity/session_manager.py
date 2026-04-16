import json
import time
import secrets
import os
from flask import request

# --------------------------
# Config
# --------------------------
SESSIONS_FILE = "data/sessions.json"
SESSION_TIMEOUT = 1800  # 30 minutes

os.makedirs("data", exist_ok=True)

# --------------------------
# JSON Helpers
# --------------------------
def load_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_sessions(data):
    with open(SESSIONS_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --------------------------
# Session Manager Class
# --------------------------
class SessionManager:
    def __init__(self, timeout=SESSION_TIMEOUT):
        self.timeout = timeout

    # --------------------------
    # Create Session
    # --------------------------
    def create_session(self, user_id):
        sessions = load_sessions()

        token = secrets.token_urlsafe(32)

        sessions[token] = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get("User-Agent")
        }

        save_sessions(sessions)
        return token

    # --------------------------
    # Validate Session
    # --------------------------
    def validate_session(self, token):
        sessions = load_sessions()

        if not token or token not in sessions:
            return None

        session = sessions[token]

        # Timeout check
        if time.time() - session["last_activity"] > self.timeout:
            self.destroy_session(token)
            return None

        # Optional IP check (can disable if needed)
        # if session["ip_address"] != request.remote_addr:
        #     return None

        # Update last activity (sliding expiration)
        session["last_activity"] = time.time()
        sessions[token] = session
        save_sessions(sessions)

        return session

    # --------------------------
    # Destroy Session
    # --------------------------
    def destroy_session(self, token):
        sessions = load_sessions()

        if token in sessions:
            del sessions[token]
            save_sessions(sessions)

    # --------------------------
    # Cleanup Expired Sessions
    # --------------------------
    def cleanup_expired_sessions(self):
        sessions = load_sessions()
        now = time.time()

        expired_tokens = [
            token for token, session in sessions.items()
            if now - session["last_activity"] > self.timeout
        ]

        for token in expired_tokens:
            del sessions[token]

        save_sessions(sessions)

    # --------------------------
    # Get Active Sessions (Admin Use)
    # --------------------------
    def get_active_sessions(self):
        return load_sessions()

    # --------------------------
    # Destroy All Sessions for User
    # --------------------------
    def destroy_user_sessions(self, user_id):
        sessions = load_sessions()

        tokens_to_delete = [
            token for token, session in sessions.items()
            if session["user_id"] == user_id
        ]

        for token in tokens_to_delete:
            del sessions[token]

        save_sessions(sessions)
