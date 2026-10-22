"""
CVE Sentinel — Scoring CVSS
Supporte CVSS 4.0, 3.1, 3.0, 2.0 (fallback).
Retourne le meilleur score disponible avec sa version.
"""


# Ordre de priorité : CVSS 4.0 > 3.1 > 3.0 > 2.0
_METRIC_KEYS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def get_cvss(cve: dict) -> tuple[float | None, str, str]:
    """
    Retourne (score, severity, cvss_version) pour la meilleure métrique disponible.
    - score     : float ou None si aucun score trouvé
    - severity  : str ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    - cvss_version : str ("4.0", "3.1", "3.0", "2.0", "")
    """
    metrics = cve.get("metrics", {})

    for metric_key, version in _METRIC_KEYS:
        entries = metrics.get(metric_key, [])
        if not entries:
            continue

        # Préférer le score de type "Primary" si plusieurs sources
        primary = next(
            (e for e in entries if e.get("type", "").lower() == "primary"),
            entries[0],
        )
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")

        if score is not None:
            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
            vector = cvss_data.get("vectorString", "")
            return float(score), severity, version, vector

    return None, "UNKNOWN", "", ""


def severity_from_score(score: float | None) -> str:
    """Calcule la sévérité à partir du score CVSS."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def best_severity(score_severity: str, metric_severity: str) -> str:
    """Retourne la sévérité la plus élevée entre deux valeurs."""
    a = _SEVERITY_ORDER.get(score_severity, -1)
    b = _SEVERITY_ORDER.get(metric_severity, -1)
    return score_severity if a >= b else metric_severity
