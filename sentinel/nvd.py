from datetime import datetime, timedelta, timezone
import requests

from .config import NVD_URL, NVD_API_KEY


def fetch_recent(hours=27):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    headers = {"User-Agent": "CVE-Sentinel/1.0"}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    response = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
    response.raise_for_status()

    return response.json().get("vulnerabilities", [])
