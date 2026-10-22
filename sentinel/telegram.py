"""
CVE Sentinel — Notification Telegram
Utilise uniquement TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID depuis les secrets GitHub.
Aucun token n'est codé en dur.
"""
import logging
import time

import requests

from .config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 5
# Limite Telegram : 4096 chars par message
TELEGRAM_MAX_LEN = 4096


def enabled() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def _escape_html(text: str) -> str:
    """Échappe les caractères HTML pour le mode parse_mode=HTML."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )


def send(text: str) -> bool:
    """
    Envoie un message Telegram.
    Retourne True si succès, False sinon (erreur loggée mais non propagée).
    """
    if not enabled():
        logger.debug("Telegram désactivé (pas de token/chat_id).")
        return False

    # Tronquer si nécessaire
    if len(text) > TELEGRAM_MAX_LEN:
        text = text[: TELEGRAM_MAX_LEN - 4] + "\n…"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.post(
                url,
                data={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=30,
            )

            if response.status_code == 429:
                retry_after = response.json().get("parameters", {}).get("retry_after", 10)
                logger.warning("Telegram rate limit. Attente %ds.", retry_after)
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            return True

        except requests.exceptions.RequestException as exc:
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "Erreur Telegram (tentative %d/%d) : %s. Retry dans %ds.",
                    attempt + 1, MAX_RETRIES, exc, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "Impossible d'envoyer sur Telegram après %d tentatives : %s",
                    MAX_RETRIES + 1, exc,
                )
                return False

    return False


def send_bulk(messages: list[str]) -> int:
    """
    Envoie une liste de messages Telegram.
    Retourne le nombre de messages envoyés avec succès.
    """
    sent = 0
    for msg in messages:
        if send(msg):
            sent += 1
            # Pause entre les messages pour éviter le rate limit
            if len(messages) > 1:
                time.sleep(0.5)
    return sent
