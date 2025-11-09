from app.core.security import hash_password, verify_password, create_access_token
from jose import jwt

def test_hash_and_verify():
    h = hash_password("S&nh@Fort3")
    assert h and isinstance(h, str)
    assert verify_password("S&nh@Fort3", h) is True

def test_create_access_token():
    token = create_access_token({"sub": "123", "role": "user"})
    assert isinstance(token, str) and len(token) > 10