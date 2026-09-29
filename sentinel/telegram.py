import requests

from .config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID


def enabled():
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def send(text):
    if not enabled():
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    response = requests.post(
        url,
        data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "disable_web_page_preview": True,
        },
        timeout=30,
    )
    response.raise_for_status()
