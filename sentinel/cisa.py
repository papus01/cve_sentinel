import requests

from .config import CISA_KEV_URL


def fetch_kev():
    response = requests.get(
        CISA_KEV_URL,
        headers={"User-Agent": "CVE-Sentinel/1.0"},
        timeout=60,
    )
    response.raise_for_status()

    data = response.json()

    return {
        item["cveID"]: item
        for item in data.get("vulnerabilities", [])
        if item.get("cveID")
    }
