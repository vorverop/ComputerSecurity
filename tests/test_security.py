import requests

BASE = "https://localhost:5000"

def test_xss():
    res = requests.post(
        f"{BASE}/register",
        json={
            "username": "<script>alert(1)</script>",
            "email": "bad@test.com",
            "password": "StrongPass123!"
        },
        verify=False
    )
    print("XSS test:", res.text)

def test_path_traversal():
    res = requests.get(
        f"{BASE}/download/../../app.py",
        verify=False
    )
    print("Path traversal:", res.text)

if __name__ == "__main__":
    test_xss()
    test_path_traversal()
