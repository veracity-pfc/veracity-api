from app.services.auth_service import validate_password_policy, six_digit_code

def test_validate_password_policy():
    assert validate_password_policy("Abcdef1!") is None  

def test_six_digit_code():
    code = six_digit_code()
    assert code.isdigit() and len(code) == 6
