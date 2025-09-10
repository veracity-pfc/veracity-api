import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

IPQS_API_KEY = os.getenv("IPQS_API_KEY")
IPQS_BASE_URL = "https://www.ipqualityscore.com/"
IPQS_API_URL = "https://ipqualityscore.com/api/json/url"

GOOGLE_SAFE_BROWSING_BASE_URL = "https://safebrowsing.google.com/"
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

HTTP_TIMEOUT = 6
HTTP_USER_AGENT = "veracity-pfc/1.0 (+https://github.com/veracity-pfc/veracity-api)"

TLD_CACHE_TTL = timedelta(hours=24)
TLD_CACHE_FILE = Path(".cache/tlds-alpha-by-domain.txt")
IANA_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

MAX_URL_LENGTH = 200

URL_EXAMPLE = "https://exemplo.com.br/"
