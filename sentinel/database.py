import json
import os
from datetime import datetime, timezone

from .config import CVE_FILE, STATS_FILE, STATE_FILE, DATA_DIR


def ensure_data():
    os.makedirs(DATA_DIR, exist_ok=True)


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)


def load_cves():
    return load_json(CVE_FILE, [])


def save_cves(cves):
    save_json(CVE_FILE, cves)


def load_state():
    return load_json(STATE_FILE, {"sent": []})


def save_state(state):
    save_json(STATE_FILE, state)


def save_stats(cves):
    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(cves),
        "critical": sum(x.get("severity") == "CRITICAL" for x in cves),
        "high": sum(x.get("severity") == "HIGH" for x in cves),
        "medium": sum(x.get("severity") == "MEDIUM" for x in cves),
        "low": sum(x.get("severity") == "LOW" for x in cves),
        "unknown": sum(x.get("severity") == "UNKNOWN" for x in cves),
        "kev": sum(x.get("kev") for x in cves),
    }

    save_json(STATS_FILE, stats)
