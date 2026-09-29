import os

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
EMAIL_TO = os.getenv("EMAIL_TO", "").strip()

MIN_CVSS = float(os.getenv("MIN_CVSS", "0") or 0)
MAX_CVES = int(os.getenv("MAX_CVES", "30") or 30)
SEND_EMPTY_REPORT = os.getenv("SEND_EMPTY_REPORT", "false").lower() == "true"

KEYWORDS = [
    x.strip().lower()
    for x in os.getenv("KEYWORDS", "").split(",")
    if x.strip()
]

DATA_DIR = "data"
CVE_FILE = f"{DATA_DIR}/cves.json"
STATS_FILE = f"{DATA_DIR}/stats.json"
STATE_FILE = f"{DATA_DIR}/state.json"
