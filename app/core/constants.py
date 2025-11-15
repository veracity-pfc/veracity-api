import re

ALLOWED_MIMES = {"image/png", "image/jpeg"}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PASSWORD_POLICY = re.compile(r"^(?=.{8,30}$)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*\W).+$")

IANA_TTL_SEC = 24 * 60 * 60
IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

HAS_DIGIT_RE = re.compile(r"\d")

GENERIC_ANALYSIS_ERROR = "Não foi possível processar a análise agora. Tente novamente mais tarde."

RESEND_API = "https://api.resend.com/emails"

DNS_TIMEOUT = 1.2
