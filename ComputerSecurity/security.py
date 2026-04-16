import re
import html
import os
from flask import request, redirect

# --------------------------
# INPUT SANITIZATION
# --------------------------

def sanitize_input(user_input):
    """Escape HTML special characters (XSS prevention)"""
    if isinstance(user_input, str):
        return html.escape(user_input)
    return user_input


def sanitize_dict(data):
    """Sanitize all string values in a dict"""
    if not isinstance(data, dict):
        return data

    return {
        k: sanitize_input(v) if isinstance(v, str) else v
        for k, v in data.items()
    }

# --------------------------
# VALIDATION FUNCTIONS
# --------------------------

def validate_username(username):
    """3–20 chars, alphanumeric + underscore"""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))


def validate_email(email):
    """Basic email validation"""
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


def validate_password(password):
    """Strong password policy"""
    return (
            isinstance(password, str) and
            len(password) >= 12 and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*" for c in password)
    )


def validate_filename(filename):
    """Allow only safe filenames"""
    return bool(re.match(r'^[\w\-. ]+$', filename))


def validate_role(role):
    """Valid roles"""
    return role in ["admin", "user", "guest", "viewer", "editor"]

# --------------------------
# PATH TRAVERSAL PROTECTION
# --------------------------

def safe_file_path(user_filename, base_dir):
    """
    Prevent path traversal attacks
    Ensures file stays inside base_dir
    """
    # Remove directory components
    filename = os.path.basename(user_filename)

    # Allow only safe characters
    if not validate_filename(filename):
        raise ValueError("Invalid filename")

    full_path = os.path.join(base_dir, filename)

    # Ensure path is inside base_dir
    if not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):
        raise ValueError("Path traversal detected")

    return full_path

# --------------------------
# LENGTH / TYPE CHECKS
# --------------------------

def validate_length(value, min_len=1, max_len=255):
    if not isinstance(value, str):
        return False
    return min_len <= len(value) <= max_len


def validate_integer(value, min_val=None, max_val=None):
    try:
        val = int(value)
    except:
        return False

    if min_val is not None and val < min_val:
        return False
    if max_val is not None and val > max_val:
        return False

    return True

# --------------------------
# HTTPS ENFORCEMENT
# --------------------------

def enforce_https(app):
    @app.before_request
    def redirect_to_https():
        if not request.is_secure and app.env != "development":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

# --------------------------
# SECURITY HEADERS
# --------------------------

def apply_security_headers(app):
    @app.after_request
    def set_headers(response):
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Clickjacking protection
        response.headers['X-Frame-Options'] = 'DENY'

        # MIME sniffing prevention
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # XSS protection (legacy)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions policy
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )

        # HSTS (force HTTPS)
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )

        return response

# --------------------------
# FILE UPLOAD VALIDATION
# --------------------------

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "docx"
}

def allowed_file(filename):
    return (
            '.' in filename and
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def validate_file_upload(file):
    if not file:
        raise ValueError("No file provided")

    filename = file.filename

    if not validate_filename(filename):
        raise ValueError("Invalid filename")

    if not allowed_file(filename):
        raise ValueError("File type not allowed")

    # Optional: limit file size (Flask config preferred)
    # if file.content_length > 5 * 1024 * 1024:
    #     raise ValueError("File too large")

    return True

# --------------------------
# GENERIC ERROR RESPONSE
# --------------------------

def safe_error(message="An error occurred"):
    """Return generic error message (avoid leaking details)"""
    return {"error": message}
