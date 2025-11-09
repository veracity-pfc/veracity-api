from app.services.email_service import verification_email_html

def test_verification_email_html_success():
    html = verification_email_html("Manu", "123456")
    assert "Manu" in html
    assert "1 2 3 4 5 6" in html
