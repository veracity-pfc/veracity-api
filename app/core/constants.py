import re

ALLOWED_MIMES = {"image/png", "image/jpeg", "image.jpg"}

CODE_RE = re.compile(r"^\d{6}$")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PASSWORD_POLICY = re.compile(r"^(?=.{8,30}$)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*\W).+$")

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

SIGHTENGINE_API_URL = "https://api.sightengine.com/1.0/check.json"

HAS_DIGIT_RE = re.compile(r"\d")

GENERIC_ANALYSIS_ERROR = "Não foi possível processar a análise agora. Tente novamente mais tarde."

RESEND_API = "https://api.resend.com/emails"

DNS_TIMEOUT = 1.2

DEFAULT_TOKEN_TTL_DAYS = 90
TOKEN_PREFIX = "vera"