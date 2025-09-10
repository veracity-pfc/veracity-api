from app.utils.validators import is_valid_url
from app.utils.constants import URL_EXAMPLE

def test_valid_link():
    assert is_valid_url(URL_EXAMPLE) is True

def test_invalid_characters():
    assert is_valid_url(f"{URL_EXAMPLE}<script>") is False

def test_long_url():
    long_url = URL_EXAMPLE + "a" * 500
    assert is_valid_url(long_url) is False
