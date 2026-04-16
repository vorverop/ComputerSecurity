import os
import json
import time
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

# --------------------------
# Paths / Files
# --------------------------
DATA_DIR = "data"
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
FILES_FILE = os.path.join(DATA_DIR, "files.json")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")

os.makedirs(UPLOAD_DIR, exist_ok=True)

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
# Encryption Setup
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
# File Path Safety
# --------------------------
def safe_filename(filename):
    filename = secure_filename(filename)

    if not filename:
        raise ValueError("Invalid filename")

    return filename

def build_file_path(filename, version):
    base = safe_filename(filename)
    return os.path.join(UPLOAD_DIR, f"{base}_v{version}.enc")

# --------------------------
# File Metadata
# --------------------------
def init_file_metadata(filename, owner):
    files = load_json(FILES_FILE)

    files[filename] = {
        "owner": owner,
        "versions": 1,
        "shared_with": {},  # user: role
        "audit_log": [
            {
                "timestamp": time.time(),
                "user": owner,
                "action": "created"
            }
        ]
    }

    save_json(FILES_FILE, files)

# --------------------------
# Upload (Encrypted + Versioning)
# --------------------------
def save_file(file_obj, filename, user):
    filename = safe_filename(filename)
    files = load_json(FILES_FILE)

    # Read file data
    raw_data = file_obj.read()
    encrypted = cipher.encrypt(raw_data)

    # New file
    if filename not in files:
        version = 1
        init_file_metadata(filename, user)
    else:
        version = files[filename]["versions"] + 1
        files[filename]["versions"] = version

    path = build_file_path(filename, version)

    with open(path, "wb") as f:
        f.write(encrypted)

    # Audit log
    files = load_json(FILES_FILE)
    files[filename]["audit_log"].append({
        "timestamp": time.time(),
        "user": user,
        "action": f"uploaded_v{version}"
    })

    save_json(FILES_FILE, files)

    return {"filename": filename, "version": version}

# --------------------------
# Download (Decrypt)
# --------------------------
def load_file(filename, user):
    filename = safe_filename(filename)
    files = load_json(FILES_FILE)

    if filename not in files:
        raise ValueError("File not found")

    if not has_access(user, filename, "read"):
        raise PermissionError("Access denied")

    version = files[filename]["versions"]
    path = build_file_path(filename, version)

    if not os.path.exists(path):
        raise FileNotFoundError("Missing file data")

    with open(path, "rb") as f:
        encrypted = f.read()

    decrypted = cipher.decrypt(encrypted)

    # Audit log
    files[filename]["audit_log"].append({
        "timestamp": time.time(),
        "user": user,
        "action": "download"
    })
    save_json(FILES_FILE, files)

    return decrypted

# --------------------------
# Access Control
# --------------------------
def has_access(user, filename, action):
    files = load_json(FILES_FILE)

    if filename not in files:
        return False

    file_meta = files[filename]

    # Owner has full access
    if file_meta["owner"] == user:
        return True

    shared = file_meta.get("shared_with", {})

    if user not in shared:
        return False

    role = shared[user]

    if role == "viewer":
        return action == "read"

    if role == "editor":
        return action in ["read", "write"]

    return False

# --------------------------
# Share File
# --------------------------
def share_file(filename, owner, target_user, role):
    filename = safe_filename(filename)
    files = load_json(FILES_FILE)

    if filename not in files:
        raise ValueError("File not found")

    if files[filename]["owner"] != owner:
        raise PermissionError("Only owner can share")

    if role not in ["viewer", "editor"]:
        raise ValueError("Invalid role")

    files[filename]["shared_with"][target_user] = role

    files[filename]["audit_log"].append({
        "timestamp": time.time(),
        "user": owner,
        "action": f"shared_with_{target_user}_{role}"
    })

    save_json(FILES_FILE, files)

# --------------------------
# List Files (User View)
# --------------------------
def list_files(user):
    files = load_json(FILES_FILE)

    result = []

    for fname, meta in files.items():
        if meta["owner"] == user or user in meta["shared_with"]:
            result.append({
                "filename": fname,
                "owner": meta["owner"],
                "version": meta["versions"],
                "role": (
                    "owner" if meta["owner"] == user
                    else meta["shared_with"][user]
                )
            })

    return result

# --------------------------
# Delete File
# --------------------------
def delete_file(filename, user):
    filename = safe_filename(filename)
    files = load_json(FILES_FILE)

    if filename not in files:
        raise ValueError("File not found")

    if files[filename]["owner"] != user:
        raise PermissionError("Only owner can delete")

    versions = files[filename]["versions"]

    # Delete all versions
    for v in range(1, versions + 1):
        path = build_file_path(filename, v)
        if os.path.exists(path):
            os.remove(path)

    del files[filename]
    save_json(FILES_FILE, files)

# --------------------------
# Get Audit Log
# --------------------------
def get_audit_log(filename, user):
    filename = safe_filename(filename)
    files = load_json(FILES_FILE)

    if filename not in files:
        raise ValueError("File not found")

    if files[filename]["owner"] != user:
        raise PermissionError("Only owner can view audit log")

    return files[filename]["audit_log"]
