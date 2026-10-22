"""
CVE Sentinel — Module de persistance (database)
Gère :
- cves.json      : historique complet des CVE (dashboard)
- stats.json     : statistiques agrégées
- state.json     : état inter-exécutions (dernière collecte, CVE notifiées)
"""
import json
import logging
import os
from datetime import datetime, timezone

from .config import CVE_FILE, STATS_FILE, STATE_FILE, DATA_DIR

logger = logging.getLogger(__name__)


def ensure_data():
    """Crée le répertoire data/ si nécessaire."""
    os.makedirs(DATA_DIR, exist_ok=True)


# ── Utilitaires JSON ──────────────────────────────────────────────────────────

def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Impossible de lire %s (%s). Valeur par défaut utilisée.", path, exc)
        return default


def save_json(path: str, value) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(value, fh, ensure_ascii=False, indent=2)
    except OSError as exc:
        logger.error("Impossible d'écrire %s : %s", path, exc)
        raise


# ── CVE history ───────────────────────────────────────────────────────────────

def load_cves() -> list[dict]:
    return load_json(CVE_FILE, [])


def save_cves(cves: list[dict]) -> None:
    save_json(CVE_FILE, cves)


# ── Stats ─────────────────────────────────────────────────────────────────────

def save_stats(cves: list[dict]) -> None:
    now = datetime.now(timezone.utc)

    # CVE détectées aujourd'hui (UTC)
    today = now.date().isoformat()
    today_count = sum(
        1 for c in cves
        if (c.get("detected_at") or c.get("published") or "").startswith(today)
    )

    stats = {
        "generated_at": now.isoformat(),
        "total": len(cves),
        "today": today_count,
        "critical": sum(c.get("severity") == "CRITICAL" for c in cves),
        "high": sum(c.get("severity") == "HIGH" for c in cves),
        "medium": sum(c.get("severity") == "MEDIUM" for c in cves),
        "low": sum(c.get("severity") == "LOW" for c in cves),
        "unknown": sum(c.get("severity") == "UNKNOWN" for c in cves),
        "kev": sum(bool(c.get("kev")) for c in cves),
    }
    save_json(STATS_FILE, stats)
    return stats


# ── State (inter-run) ─────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Structure du state :
    {
      "last_successful_run": "2026-10-22T08:17:00+00:00",
      "notified": {
        "CVE-2026-XXXXX": {
          "telegram_at": "...",
          "email_at": "...",
          "severity": "CRITICAL",
          "cvss": 9.8
        }
      }
    }
    """
    data = load_json(STATE_FILE, {})
    # Migration depuis l'ancien format {"sent": [...]}
    if "sent" in data and "notified" not in data:
        logger.info("Migration state.json ancien format → nouveau format.")
        notified = {cve_id: {"telegram_at": "migrated"} for cve_id in data["sent"]}
        data = {"notified": notified}
    if "notified" not in data:
        data["notified"] = {}
    return data


def save_state(state: dict) -> None:
    # Limiter l'historique des notifications à 50 000 entrées
    if len(state.get("notified", {})) > 50_000:
        # Garder les plus récentes (tri par telegram_at)
        items = sorted(
            state["notified"].items(),
            key=lambda kv: kv[1].get("telegram_at", ""),
            reverse=True,
        )
        state["notified"] = dict(items[:50_000])
    save_json(STATE_FILE, state)
