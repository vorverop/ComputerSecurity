import requests

BASE = "https://localhost:5000"

def test_register():
    res = requests.post(
        f"{BASE}/register",
        json={
            "username": "testuser1",
            "email": "test1@test.com",
            "password": "StrongPass123!"
        },
        verify=False
    )
    print("Register:", res.text)

def test_login():
    res = requests.post(
        f"{BASE}/login",
        json={
            "username": "testuser1",
            "password": "StrongPass123!"
        },
        verify=False
    )
    print("Login:", res.text)

if __name__ == "__main__":
    test_register()
    test_login()
