"""
CVE Sentinel — Module CISA KEV
Récupère le catalogue CISA Known Exploited Vulnerabilities avec retry.
"""
import logging
import time

import requests

from .config import CISA_KEV_URL

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 5


def fetch_kev() -> dict[str, dict]:
    """
    Retourne un dictionnaire {cve_id: kev_entry} du catalogue CISA KEV.
    Inclut : vendorProject, product, vulnerabilityName, dateAdded,
             shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse.
    """
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.get(
                CISA_KEV_URL,
                headers={"User-Agent": "CVE-Sentinel/2.0"},
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()

            kev_map = {
                item["cveID"]: item
                for item in data.get("vulnerabilities", [])
                if item.get("cveID")
            }
            logger.info("CISA KEV : %d entrées chargées.", len(kev_map))
            return kev_map

        except requests.exceptions.RequestException as exc:
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "Erreur CISA KEV (tentative %d/%d) : %s. Retry dans %ds.",
                    attempt + 1, MAX_RETRIES, exc, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "Impossible de charger CISA KEV après %d tentatives : %s",
                    MAX_RETRIES + 1, exc,
                )
                return {}

    return {}
