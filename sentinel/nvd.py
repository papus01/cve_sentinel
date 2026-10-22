"""
CVE Sentinel — Collecteur NVD API 2.0
- Pagination complète (startIndex / resultsPerPage)
- Retry avec backoff exponentiel
- Gestion des erreurs HTTP (429, 503, etc.)
- Fenêtre temporelle robuste basée sur la dernière exécution réussie
- Support NVD_API_KEY
"""
import logging
import time
from datetime import datetime, timedelta, timezone

import requests

from .config import NVD_URL, NVD_API_KEY, LOOKBACK_HOURS, MAX_LOOKBACK_DAYS

logger = logging.getLogger(__name__)

# L'API NVD autorise 2000 résultats par page sans clé, 2000 avec clé.
RESULTS_PER_PAGE = 2000

# Délai minimum entre deux appels NVD (sans clé : 6s, avec clé : 0.6s)
# On prend une marge de sécurité.
REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.5

MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 10  # secondes


def _headers():
    h = {"User-Agent": "CVE-Sentinel/2.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _fetch_page(params: dict, attempt: int = 0) -> dict:
    """Effectue un appel API NVD avec retry exponentiel."""
    try:
        response = requests.get(
            NVD_URL,
            params=params,
            headers=_headers(),
            timeout=90,
        )

        if response.status_code == 429:
            wait = RETRY_BACKOFF_BASE * (2 ** attempt)
            logger.warning("NVD rate limit (429). Attente %ds avant retry.", wait)
            time.sleep(wait)
            if attempt < MAX_RETRIES:
                return _fetch_page(params, attempt + 1)
            raise RuntimeError("NVD rate limit persistant après %d tentatives." % MAX_RETRIES)

        if response.status_code in (503, 502, 504):
            wait = RETRY_BACKOFF_BASE * (2 ** attempt)
            logger.warning(
                "NVD indisponible (%d). Attente %ds avant retry.",
                response.status_code, wait,
            )
            time.sleep(wait)
            if attempt < MAX_RETRIES:
                return _fetch_page(params, attempt + 1)
            raise RuntimeError("NVD indisponible après %d tentatives." % MAX_RETRIES)

        response.raise_for_status()
        return response.json()

    except requests.exceptions.Timeout:
        wait = RETRY_BACKOFF_BASE * (2 ** attempt)
        logger.warning("Timeout NVD. Attente %ds avant retry.", wait)
        time.sleep(wait)
        if attempt < MAX_RETRIES:
            return _fetch_page(params, attempt + 1)
        raise

    except requests.exceptions.ConnectionError:
        wait = RETRY_BACKOFF_BASE * (2 ** attempt)
        logger.warning("Erreur connexion NVD. Attente %ds avant retry.", wait)
        time.sleep(wait)
        if attempt < MAX_RETRIES:
            return _fetch_page(params, attempt + 1)
        raise


def compute_window(last_successful_run: str | None) -> tuple[datetime, datetime]:
    """
    Calcule la fenêtre temporelle de collecte.

    - Si une dernière exécution est connue, on recule de LOOKBACK_HOURS
      pour éviter les CVE manquées entre deux runs.
    - Si le dernier run est très ancien (> MAX_LOOKBACK_DAYS), on prend
      MAX_LOOKBACK_DAYS pour ne pas exploser le volume d'un coup.
    - Si aucun run précédent, on prend LOOKBACK_HOURS comme fenêtre initiale.
    """
    now = datetime.now(timezone.utc)
    max_past = now - timedelta(days=MAX_LOOKBACK_DAYS)

    if last_successful_run:
        try:
            last = datetime.fromisoformat(last_successful_run)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            # Recul de sécurité pour couvrir les CVE publiées juste avant le run
            start = last - timedelta(hours=LOOKBACK_HOURS)
            # Ne pas remonter plus loin que MAX_LOOKBACK_DAYS
            start = max(start, max_past)
        except ValueError:
            logger.warning("Format de date invalide pour last_run: %s", last_successful_run)
            start = now - timedelta(hours=LOOKBACK_HOURS)
    else:
        start = now - timedelta(hours=LOOKBACK_HOURS)

    return start, now


def fetch_recent(start: datetime, end: datetime) -> list[dict]:
    """
    Récupère toutes les CVE publiées entre `start` et `end`.
    Gère la pagination complète de l'API NVD 2.0.
    Retourne la liste brute des objets `vulnerability`.
    """
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%S.999")

    logger.info(
        "NVD collection | Fenêtre : %s → %s",
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    all_vulns = []
    start_index = 0
    page = 1
    total_results = None

    while True:
        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        logger.info("Page %d (startIndex=%d)…", page, start_index)
        data = _fetch_page(params)

        vulns = data.get("vulnerabilities", [])
        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info("Total NVD annoncé : %d CVE", total_results)

        if not vulns:
            logger.info("Page %d : vide. Fin de pagination.", page)
            break

        logger.info("Page %d : %d CVE reçues.", page, len(vulns))
        all_vulns.extend(vulns)

        start_index += len(vulns)
        page += 1

        # Vérification de fin de pagination
        if start_index >= total_results:
            break

        # Respecter les limites de l'API NVD
        time.sleep(REQUEST_DELAY)

    logger.info("Total récupéré depuis NVD : %d CVE.", len(all_vulns))
    return all_vulns
