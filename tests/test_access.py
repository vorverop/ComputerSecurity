import requests

BASE = "https://localhost:5000"

def test_unauthorized_download():
    res = requests.get(
        f"{BASE}/download/test.txt",
        verify=False
    )
    print("Unauthorized access:", res.text)

if __name__ == "__main__":
    test_unauthorized_download()
