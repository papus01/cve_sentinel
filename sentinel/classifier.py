"""
CVE Sentinel — Classification des CVE
Fonction centralisée classify_cve() qui détermine la priorité et la politique de notification.
Ne filtre JAMAIS la collecte : toute CVE est normalisée et enregistrée.
"""
from .config import (
    ALERT_ALL_NEW_CVES,
    ALERT_CRITICAL,
    ALERT_HIGH,
    ALERT_MEDIUM,
    ALERT_LOW,
    ALERT_KEV,
    KEYWORDS,
    MIN_CVSS,
)


_PRIORITY_MAP = {
    "CRITICAL": "URGENT",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "LOW",
}


def matches_keywords(cve_id: str, text: str) -> bool:
    """
    Détermine si une CVE correspond aux mots-clés configurés.
    NE FILTRE PAS la collecte. Sert uniquement à la mise en avant.
    Retourne True si KEYWORDS est vide (toutes les CVE sont pertinentes).
    """
    if not KEYWORDS:
        return True
    haystack = f"{cve_id} {text}".lower()
    return any(keyword in haystack for keyword in KEYWORDS)


def classify_cve(cve: dict) -> dict:
    """
    Détermine la classification complète d'une CVE normalisée.

    Paramètre : CVE normalisée (sortie de normalize() dans main.py)

    Retourne :
    {
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN",
        "priority": "URGENT" | "HIGH" | "MEDIUM" | "LOW",
        "is_kev": bool,
        "matches_keywords": bool,
        "should_notify": bool,
        "notify_reason": str,   # Pour les logs
    }
    """
    severity = cve.get("severity", "UNKNOWN")
    cvss = cve.get("cvss")
    is_kev = bool(cve.get("kev"))

    priority = _PRIORITY_MAP.get(severity, "LOW")

    # Recalcul de sévérité si score disponible (protection contre incohérences)
    if cvss is not None:
        if cvss >= 9.0:
            severity = "CRITICAL"
            priority = "URGENT"
        elif cvss >= 7.0:
            severity = max_severity(severity, "HIGH")
            priority = max_priority(priority, "HIGH")
        elif cvss >= 4.0:
            severity = max_severity(severity, "MEDIUM")
        else:
            pass  # LOW déjà défini

    # CVE KEV → toujours au moins HIGH priority
    if is_kev:
        priority = max_priority(priority, "HIGH")

    # Détermination de should_notify
    should_notify = False
    notify_reason = ""

    if ALERT_ALL_NEW_CVES:
        should_notify = True
        notify_reason = "ALERT_ALL_NEW_CVES=true"

    elif is_kev and ALERT_KEV:
        should_notify = True
        notify_reason = "CISA KEV"

    elif severity == "CRITICAL" and ALERT_CRITICAL:
        should_notify = True
        notify_reason = "CRITICAL severity"

    elif severity == "HIGH" and ALERT_HIGH:
        should_notify = True
        notify_reason = "HIGH severity"

    elif severity == "MEDIUM" and ALERT_MEDIUM:
        should_notify = True
        notify_reason = "MEDIUM severity"

    elif severity == "LOW" and ALERT_LOW:
        should_notify = True
        notify_reason = "LOW severity"

    # MIN_CVSS : si configuré, peut réduire les notifications
    # mais ne supprime JAMAIS la collecte
    if cvss is not None and cvss < MIN_CVSS and not is_kev:
        should_notify = False
        notify_reason = f"cvss {cvss:.1f} < MIN_CVSS {MIN_CVSS} (KEV override=False)"

    kw_match = matches_keywords(cve.get("id", ""), cve.get("description", ""))

    return {
        "severity": severity,
        "priority": priority,
        "is_kev": is_kev,
        "matches_keywords": kw_match,
        "should_notify": should_notify,
        "notify_reason": notify_reason,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_PRI_ORDER = {"URGENT": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def max_severity(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


def max_priority(a: str, b: str) -> str:
    return a if _PRI_ORDER.get(a, 0) >= _PRI_ORDER.get(b, 0) else b
