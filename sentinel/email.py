import smtplib
from email.message import EmailMessage

from .config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    EMAIL_FROM,
    EMAIL_TO,
)


def enabled():
    return bool(SMTP_HOST and EMAIL_FROM and EMAIL_TO)


def send(subject, body):
    if not enabled():
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = EMAIL_FROM
    message["To"] = EMAIL_TO
    message.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)
