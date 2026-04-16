import os

# --------------------------
# ENVIRONMENT
# --------------------------
ENV = os.getenv("APP_ENV", "development")

DEBUG = ENV == "development"

# --------------------------
# SERVER SETTINGS
# --------------------------
HOST = "0.0.0.0"
PORT = 5000

# TLS / HTTPS
SSL_CERT = os.getenv("SSL_CERT", "cert.pem")
SSL_KEY = os.getenv("SSL_KEY", "key.pem")

# --------------------------
# PATHS
# --------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
FILES_FILE = os.path.join(DATA_DIR, "files.json")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")

# Ensure directories exist
for directory in [DATA_DIR, LOG_DIR, UPLOAD_DIR]:
    os.makedirs(directory, exist_ok=True)

# --------------------------
# AUTH / SECURITY SETTINGS
# --------------------------
BCRYPT_ROUNDS = 12

SESSION_TIMEOUT = 1800  # 30 minutes
SESSION_COOKIE_NAME = "session_token"

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

# Rate limiting
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10     # attempts per window

# --------------------------
# PASSWORD POLICY
# --------------------------
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPER = True
PASSWORD_REQUIRE_LOWER = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True

# --------------------------
# FILE UPLOAD SETTINGS
# --------------------------
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "docx"
}

# --------------------------
# ENCRYPTION SETTINGS
# --------------------------
ENCRYPTION_ENABLED = True

# --------------------------
# SECURITY HEADERS CONFIG
# --------------------------
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

HSTS_MAX_AGE = 31536000

# --------------------------
# LOGGING SETTINGS
# --------------------------
SECURITY_LOG_FILE = os.path.join(LOG_DIR, "security.log")
ACCESS_LOG_FILE = os.path.join(LOG_DIR, "access.log")

LOG_LEVEL = "INFO"

# --------------------------
# RBAC SETTINGS
# --------------------------
ROLES = ["admin", "user", "guest"]

FILE_PERMISSIONS = {
    "owner": ["read", "write", "delete", "share"],
    "editor": ["read", "write"],
    "viewer": ["read"]
}

# --------------------------
# MISC
# --------------------------
APP_NAME = "Secure Document Sharing System"
VERSION = "1.0.0"
