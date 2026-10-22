"""
CVE Sentinel — Notification Email
Envoie un rapport HTML professionnel via SMTP.
"""
import logging
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

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return bool(SMTP_HOST and EMAIL_FROM and EMAIL_TO)


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#ff4d6d",
        "HIGH": "#ff9f43",
        "MEDIUM": "#ffd166",
        "LOW": "#6ee7b7",
    }.get(severity, "#8996a3")


def _build_html(subject: str, items: list[dict], stats: dict) -> str:
    """Construit un rapport HTML professionnel."""
    date_str = stats.get("date", "")
    total = stats.get("total_new", len(items))

    rows = ""
    for item in items[:200]:  # cap à 200 lignes dans l'email
        color = _severity_color(item.get("severity", "UNKNOWN"))
        score = item.get("cvss")
        score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
        kev_badge = (
            '<span style="background:#b084ff22;color:#b084ff;padding:2px 6px;border-radius:4px;font-size:11px;">CISA KEV</span>'
            if item.get("kev") else ""
        )
        desc = (item.get("description") or "")[:300]
        rows += f"""
        <tr>
          <td style="padding:10px;border-bottom:1px solid #1b2630;">
            <a href="{item.get('url','')}" style="color:#49d6ff;font-weight:700;">{item.get('id','')}</a>
            {kev_badge}
          </td>
          <td style="padding:10px;border-bottom:1px solid #1b2630;color:{color};font-weight:700;">
            {item.get('severity','UNKNOWN')}
          </td>
          <td style="padding:10px;border-bottom:1px solid #1b2630;font-weight:700;color:{color};">
            {score_str}
          </td>
          <td style="padding:10px;border-bottom:1px solid #1b2630;color:#b6c0ca;font-size:12px;">
            {desc}{'…' if len(item.get('description','')) > 300 else ''}
          </td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{subject}</title>
</head>
<body style="margin:0;padding:0;background:#05070a;font-family:Inter,ui-sans-serif,sans-serif;color:#edf2f7;">
  <div style="max-width:900px;margin:32px auto;padding:0 16px;">

    <!-- Header -->
    <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:16px;padding:32px;margin-bottom:20px;">
      <div style="font-size:11px;letter-spacing:.18em;color:#49d6ff;font-weight:800;">CVE SENTINEL</div>
      <h1 style="font-size:28px;margin:10px 0 4px;">Security Intelligence Report</h1>
      <div style="color:#8996a3;font-size:13px;">{date_str}</div>
    </div>

    <!-- Stats -->
    <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px;">
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">Total</div>
        <div style="font-size:26px;font-weight:900;margin-top:6px;">{total}</div>
      </div>
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">Critical</div>
        <div style="font-size:26px;font-weight:900;color:#ff4d6d;margin-top:6px;">{stats.get('critical',0)}</div>
      </div>
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">High</div>
        <div style="font-size:26px;font-weight:900;color:#ff9f43;margin-top:6px;">{stats.get('high',0)}</div>
      </div>
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">Medium</div>
        <div style="font-size:26px;font-weight:900;color:#ffd166;margin-top:6px;">{stats.get('medium',0)}</div>
      </div>
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">Low</div>
        <div style="font-size:26px;font-weight:900;color:#6ee7b7;margin-top:6px;">{stats.get('low',0)}</div>
      </div>
      <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:11px;color:#8996a3;">CISA KEV</div>
        <div style="font-size:26px;font-weight:900;color:#b084ff;margin-top:6px;">{stats.get('kev',0)}</div>
      </div>
    </div>

    <!-- Table -->
    <div style="background:#0b0f14;border:1px solid #1b2630;border-radius:16px;padding:24px;">
      <h2 style="margin:0 0 18px;font-size:16px;">Priority Vulnerabilities</h2>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="border-bottom:2px solid #1b2630;">
            <th style="padding:10px;text-align:left;color:#8996a3;font-size:11px;letter-spacing:.1em;">CVE ID</th>
            <th style="padding:10px;text-align:left;color:#8996a3;font-size:11px;letter-spacing:.1em;">SEVERITY</th>
            <th style="padding:10px;text-align:left;color:#8996a3;font-size:11px;letter-spacing:.1em;">CVSS</th>
            <th style="padding:10px;text-align:left;color:#8996a3;font-size:11px;letter-spacing:.1em;">DESCRIPTION</th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="4" style="padding:20px;color:#8996a3;text-align:center;">Aucune CVE prioritaire.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div style="text-align:center;margin-top:24px;color:#8996a3;font-size:11px;">
      CVE Sentinel · NVD + CISA KEV · Automated Security Intelligence
    </div>
  </div>
</body>
</html>"""
    return html


def send(subject: str, items: list[dict], stats: dict) -> bool:
    """
    Envoie le rapport email HTML.
    `items` : liste de CVE normalisées.
    `stats` : dict avec clés total_new, critical, high, medium, low, kev, date.
    Retourne True si succès, False sinon (erreur loggée, non propagée).
    """
    if not enabled():
        logger.debug("Email désactivé (configuration SMTP incomplète).")
        return False

    try:
        html_body = _build_html(subject, items, stats)

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = EMAIL_FROM
        message["To"] = EMAIL_TO
        message.set_content(
            f"CVE Sentinel Report — {stats.get('total_new', len(items))} nouvelles CVE. "
            "Veuillez consulter la version HTML de cet email."
        )
        message.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)

        logger.info("Email envoyé : %s → %s", subject, EMAIL_TO)
        return True

    except smtplib.SMTPException as exc:
        logger.error("Erreur SMTP lors de l'envoi de l'email : %s", exc)
        return False
    except OSError as exc:
        logger.error("Erreur réseau lors de l'envoi de l'email : %s", exc)
        return False
