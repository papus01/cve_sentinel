"""
CVE Sentinel — Configuration
Toutes les valeurs proviennent d'environnement/secrets GitHub.
Aucun secret n'est codé en dur.
"""
import os

# ── API endpoints ────────────────────────────────────────────────────────────
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# ── Credentials (secrets GitHub) ────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "").strip()
EMAIL_TO = os.getenv("EMAIL_TO", "").strip()

# ── Collecte ─────────────────────────────────────────────────────────────────
# MIN_CVSS n'empêche JAMAIS la collecte. Il influence seulement les notifications.
MIN_CVSS = float(os.getenv("MIN_CVSS", "0") or 0)

# Nombre maximum de CVE *nouvelles* à traiter par exécution (protection anti-flood)
MAX_CVES = int(os.getenv("MAX_CVES", "1000") or 1000)

# Fenêtre temporelle de sécurité : on recule de N heures depuis la dernière
# exécution réussie pour ne pas rater de CVE entre deux runs.
LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "27") or 27)

# Si aucune exécution récente n'est trouvée, on recule de N jours maximum.
MAX_LOOKBACK_DAYS = int(os.getenv("MAX_LOOKBACK_DAYS", "7") or 7)

# ── Politique de notification ────────────────────────────────────────────────
# Ces variables ne filtrent PAS la collecte. Elles définissent qui est notifié.
ALERT_CRITICAL = os.getenv("ALERT_CRITICAL", "true").lower() == "true"
ALERT_HIGH = os.getenv("ALERT_HIGH", "true").lower() == "true"
ALERT_MEDIUM = os.getenv("ALERT_MEDIUM", "false").lower() == "true"
ALERT_LOW = os.getenv("ALERT_LOW", "false").lower() == "true"
ALERT_KEV = os.getenv("ALERT_KEV", "true").lower() == "true"

# Si true, TOUTES les nouvelles CVE sont notifiées (écrase les réglages ci-dessus)
ALERT_ALL_NEW_CVES = os.getenv("ALERT_ALL_NEW_CVES", "false").lower() == "true"

# Mode de notification : "individual" | "digest" | "both"
# - individual : chaque CVE prioritaire déclenche un message Telegram séparé
# - digest     : un seul résumé quotidien
# - both       : résumé + messages individuels pour CRITICAL/KEV
NOTIFICATION_MODE = os.getenv("NOTIFICATION_MODE", "both").strip().lower()

# Envoyer un rapport même si aucune nouvelle CVE n'est détectée
SEND_EMPTY_REPORT = os.getenv("SEND_EMPTY_REPORT", "false").lower() == "true"

# ── Keywords (rôle informatif uniquement — n'exclut JAMAIS une CVE) ──────────
# Sert à mettre en avant certaines CVE dans les messages et le dashboard.
KEYWORDS = [
    x.strip().lower()
    for x in os.getenv("KEYWORDS", "").split(",")
    if x.strip()
]

# ── Fichiers de données ───────────────────────────────────────────────────────
DATA_DIR = "data"
CVE_FILE = f"{DATA_DIR}/cves.json"
STATS_FILE = f"{DATA_DIR}/stats.json"
STATE_FILE = f"{DATA_DIR}/state.json"
