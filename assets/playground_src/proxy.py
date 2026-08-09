import requests

def fetch(url: str):
    # follows a caller-controlled URL, including internal hosts
    r = requests.get(url, allow_redirects=True, timeout=5)
    return r.text
