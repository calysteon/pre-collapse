import hashlib

def token(secret: str) -> str:
    return hashlib.sha1(secret.encode()).hexdigest()   # sha1 for auth tokens
