"""
CVE Sentinel — Point d'entrée principal (V2)

Pipeline :
  NVD → TOUTES les nouvelles CVE → normalisation → déduplication →
  enrichissement KEV → classification → stockage → notifications.

PRINCIPE FONDAMENTAL : aucune CVE ne disparaît silencieusement.
Les keywords ne sont JAMAIS un filtre d'exclusion global.
"""
import logging
import sys
from datetime import datetime, timezone

from .config import (
    KEYWORDS,
    MAX_CVES,
    MIN_CVSS,
    SEND_EMPTY_REPORT,
    NOTIFICATION_MODE,
    ALERT_ALL_NEW_CVES,
)
from .nvd import fetch_recent, compute_window
from .cisa import fetch_kev
from .scoring import get_cvss, severity_from_score
from .classifier import classify_cve
from .database import (
    ensure_data,
    load_cves,
    save_cves,
    load_state,
    save_state,
    save_stats,
)
from .telegram import send as telegram_send, send_bulk, enabled as telegram_enabled
from .email import send as email_send, enabled as email_enabled

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sentinel")


# ── Extraction / normalisation ────────────────────────────────────────────────

def get_description(cve: dict) -> str:
    """Extrait la description anglaise d'une CVE NVD."""
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "").strip()
    return descriptions[0].get("value", "").strip() if descriptions else ""


def get_affected_products(cve: dict) -> list[str]:
    """Extrait les CPE des configurations NVD."""
    products = []
    for node in cve.get("configurations", []):
        for node_item in node.get("nodes", []):
            for match in node_item.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    products.append(criteria)
    return products[:20]


def normalize(cve_raw: dict, kev: dict[str, dict]) -> dict | None:
    """
    Normalise une CVE brute NVD vers le format interne CVE Sentinel.
    Retourne None si la CVE n'a pas d'ID (CVE malformée ignorée).
    Jamais de crash sur une CVE individuelle.
    """
    try:
        cve_id = cve_raw.get("id")
        if not cve_id:
            return None

        score, metric_severity, cvss_version, vector = get_cvss(cve_raw)
        computed_severity = severity_from_score(score)

        # Meilleure sévérité : calculée à partir du score ou fournie par NVD
        if computed_severity != "UNKNOWN":
            severity = computed_severity
        elif metric_severity not in ("UNKNOWN", ""):
            severity = metric_severity
        else:
            severity = "UNKNOWN"

        kev_item = kev.get(cve_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        return {
            "id": cve_id,
            "published": cve_raw.get("published"),
            "modified": cve_raw.get("lastModified"),
            "detected_at": now_iso,
            "description": get_description(cve_raw),
            "cvss": score,
            "cvss_version": cvss_version,
            "cvss_vector": vector,
            "severity": severity,
            "kev": bool(kev_item),
            "kev_name": kev_item.get("vulnerabilityName", "") if kev_item else "",
            "kev_date": kev_item.get("dateAdded", "") if kev_item else "",
            "due_date": kev_item.get("dueDate", "") if kev_item else "",
            "ransomware": kev_item.get("knownRansomwareCampaignUse", "") if kev_item else "",
            "vendor": kev_item.get("vendorProject", "") if kev_item else "",
            "product": kev_item.get("product", "") if kev_item else "",
            "products": get_affected_products(cve_raw),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    except Exception as exc:  # noqa: BLE001
        cve_id = cve_raw.get("id", "UNKNOWN")
        logger.error("Erreur lors de la normalisation de %s : %s", cve_id, exc)
        return None


# ── Formatage des messages Telegram ──────────────────────────────────────────

def _esc(text: str) -> str:
    """Échappe les caractères HTML pour Telegram parse_mode=HTML."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _severity_emoji(severity: str) -> str:
    return {
        "CRITICAL": "🚨",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟢",
    }.get(severity, "⚪")


def build_individual_message(item: dict) -> str:
    """
    Construit un message Telegram individuel pour une CVE.
    Format professionnel et lisible.
    """
    severity = item.get("severity", "UNKNOWN")
    emoji = _severity_emoji(severity)
    score = item.get("cvss")
    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
    cvss_ver = item.get("cvss_version", "")

    # Description tronquée
    desc = " ".join((item.get("description") or "").split())
    if len(desc) > 450:
        desc = desc[:447] + "…"

    kev_line = (
        "🔥 <b>Exploitation connue : OUI (CISA KEV)</b>"
        if item.get("kev")
        else "ℹ️ Non listée dans CISA KEV"
    )

    kev_name = item.get("kev_name", "")
    kev_name_line = f"📛 <b>Nom :</b> {_esc(kev_name)}\n" if kev_name else ""

    due_date = item.get("due_date", "")
    due_line = f"⏰ <b>Remédiation requise avant :</b> {_esc(due_date)}\n" if due_date else ""

    product = item.get("product", "")
    vendor = item.get("vendor", "")
    product_line = ""
    if product or vendor:
        product_line = f"📦 <b>Produit :</b> {_esc(vendor + ' ' + product).strip()}\n"

    keywords_matched = KEYWORDS and any(
        kw in f"{item.get('id','')} {item.get('description','')}".lower()
        for kw in KEYWORDS
    )
    kw_line = "🏷️ <b>Correspond à vos keywords</b>\n" if keywords_matched else ""

    pub_date = (item.get("published") or "")[:10]

    return (
        f"{emoji} <b>CVE SENTINEL — {_esc(severity)}</b>\n\n"
        f"<b>{_esc(item.get('id', ''))}</b>\n\n"
        f"{product_line}"
        f"📊 <b>Sévérité :</b> {_esc(severity)}\n"
        f"💯 <b>CVSS :</b> {_esc(score_str)}"
        f"{(' (v' + _esc(cvss_ver) + ')') if cvss_ver else ''}\n"
        f"{kev_line}\n"
        f"{kev_name_line}"
        f"{due_line}"
        f"{kw_line}\n"
        f"📝 <b>Description :</b>\n{_esc(desc)}\n\n"
        f"📅 <b>Publication :</b> {_esc(pub_date)}\n\n"
        f"🔗 <a href=\"{_esc(item.get('url',''))}\">NVD Details</a>"
    )


def build_digest_message(
    new_items: list[dict],
    stats_today: dict,
    highlight_items: list[dict],
) -> str:
    """
    Construit le message de résumé quotidien (digest).
    """
    today = datetime.now(timezone.utc).strftime("%d %B %Y")
    total = len(new_items)

    cnt_critical = stats_today.get("critical", 0)
    cnt_high = stats_today.get("high", 0)
    cnt_medium = stats_today.get("medium", 0)
    cnt_low = stats_today.get("low", 0)
    cnt_kev = stats_today.get("kev", 0)

    lines = [
        "🛡️ <b>CVE SENTINEL</b>",
        "📊 <b>Daily Security Report</b>",
        "",
        f"📅 {today}",
        "",
        f"<b>Total nouvelles CVE : {total}</b>",
        "",
        f"🚨 Critical : <b>{cnt_critical}</b>",
        f"🔴 High : <b>{cnt_high}</b>",
        f"🟠 Medium : <b>{cnt_medium}</b>",
        f"🟢 Low : <b>{cnt_low}</b>",
        "",
        f"🔥 CISA KEV : <b>{cnt_kev}</b>",
    ]

    if highlight_items:
        lines.append("")
        lines.append("━━━ <b>Vulnérabilités prioritaires</b> ━━━")
        for item in highlight_items[:10]:
            score = item.get("cvss")
            score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
            emoji = _severity_emoji(item.get("severity", "UNKNOWN"))
            kev_tag = " 🔥KEV" if item.get("kev") else ""
            lines.append(
                f"\n{emoji} <b>{_esc(item.get('id',''))}</b>{kev_tag}\n"
                f"   CVSS {_esc(score_str)} · {_esc(item.get('severity',''))}\n"
                f"   <a href=\"{_esc(item.get('url',''))}\">NVD</a>"
            )

    return "\n".join(lines)


# ── Pipeline principal ────────────────────────────────────────────────────────

def main():
    ensure_data()

    logger.info("=" * 60)
    logger.info("CVE SENTINEL V2 — Démarrage")
    logger.info("=" * 60)

    # ── Chargement de l'état inter-run ────────────────────────────────────────
    state = load_state()
    notified = state.get("notified", {})
    last_run = state.get("last_successful_run")

    logger.info("Dernier run réussi : %s", last_run or "Aucun (première exécution)")

    # ── Calcul de la fenêtre temporelle ───────────────────────────────────────
    start, end = compute_window(last_run)

    # ── Collecte NVD ──────────────────────────────────────────────────────────
    logger.info("Collecte NVD en cours…")
    try:
        raw_vulns = fetch_recent(start, end)
    except Exception as exc:
        logger.critical("Impossible de contacter l'API NVD : %s", exc)
        sys.exit(1)

    total_fetched = len(raw_vulns)

    # ── Collecte CISA KEV ─────────────────────────────────────────────────────
    logger.info("Collecte CISA KEV en cours…")
    kev = fetch_kev()

    # ── Déduplication et normalisation ────────────────────────────────────────
    new_cves = []
    duplicates = 0
    errors = 0

    for wrapper in raw_vulns:
        cve_raw = wrapper.get("cve", {})
        cve_id = cve_raw.get("id")

        if not cve_id:
            errors += 1
            continue

        # Déduplication : CVE déjà dans l'historique de notifications
        if cve_id in notified:
            duplicates += 1
            continue

        try:
            normalized = normalize(cve_raw, kev)
            if normalized is None:
                errors += 1
                continue
            new_cves.append(normalized)
        except Exception as exc:  # noqa: BLE001
            logger.error("Erreur normalisation %s : %s", cve_id, exc)
            errors += 1
            continue

    # ── Classification ────────────────────────────────────────────────────────
    cnt = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "kev": 0}

    for item in new_cves:
        classification = classify_cve(item)
        item["classification"] = classification
        sev = item.get("severity", "UNKNOWN")
        cnt[sev] = cnt.get(sev, 0) + 1
        if item.get("kev"):
            cnt["kev"] += 1

    # ── Logs de collecte ──────────────────────────────────────────────────────
    logger.info("-" * 40)
    logger.info("Résultats de la collecte :")
    logger.info("  Total fetched NVD  : %d", total_fetched)
    logger.info("  Nouvelles CVE      : %d", len(new_cves))
    logger.info("  Doublons ignorés   : %d", duplicates)
    logger.info("  Erreurs CVE        : %d", errors)
    logger.info("  Critical           : %d", cnt["CRITICAL"])
    logger.info("  High               : %d", cnt["HIGH"])
    logger.info("  Medium             : %d", cnt["MEDIUM"])
    logger.info("  Low                : %d", cnt["LOW"])
    logger.info("  CISA KEV           : %d", cnt["kev"])
    logger.info("-" * 40)

    # ── Tri des CVE nouvelles ─────────────────────────────────────────────────
    new_cves.sort(
        key=lambda x: (
            x.get("kev", False),
            x.get("cvss") or -1,
        ),
        reverse=True,
    )

    # ── Mise à jour de l'historique dashboard (TOUTES les CVE nouvelles) ───────
    existing = {item["id"]: item for item in load_cves()}
    for item in new_cves:
        existing[item["id"]] = item

    all_cves = sorted(
        existing.values(),
        key=lambda x: x.get("published") or "",
        reverse=True,
    )
    all_cves = all_cves[:5000]  # Cap dashboard

    save_cves(all_cves)
    stats_all = save_stats(all_cves)

    # ── Statistiques du jour courant ───────────────────────────────────────────
    stats_today = {
        "total_new": len(new_cves),
        "critical": cnt["CRITICAL"],
        "high": cnt["HIGH"],
        "medium": cnt["MEDIUM"],
        "low": cnt["LOW"],
        "kev": cnt["kev"],
        "date": datetime.now(timezone.utc).strftime("%d %B %Y"),
    }

    # ── Sélection des CVE à notifier ──────────────────────────────────────────
    eligible_notify = [
        item for item in new_cves
        if item.get("classification", {}).get("should_notify", False)
    ]

    # MAX_CVES sert EXCLUSIVEMENT de cap de protection anti-flood pour les alertes
    # Il n'empêche JAMAIS la collecte ni le stockage de nouvelles CVE.
    if len(eligible_notify) > MAX_CVES:
        logger.warning(
            "Protection anti-flood : %d alertes éligibles, limitation à %d notifications (MAX_CVES). "
            "Toutes les %d CVE restent collectées et stockées dans l'historique.",
            len(eligible_notify), MAX_CVES, len(new_cves),
        )
        to_notify = eligible_notify[:MAX_CVES]
    else:
        to_notify = eligible_notify

    # CVE de highlight pour le digest (Critical + KEV)
    highlight = [
        item for item in new_cves
        if item.get("severity") in ("CRITICAL",) or item.get("kev")
    ]

    telegram_sent = 0
    email_sent = 0

    if new_cves or SEND_EMPTY_REPORT:
        # ── Envoi Telegram (isolé) ────────────────────────────────────────────
        if telegram_enabled():
            try:
                if NOTIFICATION_MODE in ("digest", "both"):
                    if new_cves or SEND_EMPTY_REPORT:
                        digest_msg = build_digest_message(new_cves, stats_today, highlight)
                        if telegram_send(digest_msg):
                            telegram_sent += 1

                if NOTIFICATION_MODE in ("individual", "both"):
                    individual_messages = [
                        build_individual_message(item) for item in to_notify
                    ]
                    sent_count = send_bulk(individual_messages)
                    telegram_sent += sent_count

                logger.info("Telegram : %d message(s) envoyé(s).", telegram_sent)
            except Exception as exc:  # noqa: BLE001
                logger.error("Erreur inattendue Telegram (non bloquante) : %s", exc)
        else:
            logger.info("Telegram désactivé.")

        # ── Envoi Email (isolé) ───────────────────────────────────────────────
        if email_enabled():
            try:
                if new_cves or SEND_EMPTY_REPORT:
                    subject = (
                        f"CVE Sentinel — {len(new_cves)} nouvelle(s) CVE "
                        f"({cnt['CRITICAL']} Critical, {cnt['kev']} KEV)"
                    )
                    email_items = to_notify if to_notify else new_cves[:20]
                    if email_send(subject, email_items, stats_today):
                        email_sent += 1
                logger.info("Email : %d rapport(s) envoyé(s).", email_sent)
            except Exception as exc:  # noqa: BLE001
                logger.error("Erreur inattendue Email (non bloquante) : %s", exc)
        else:
            logger.info("Email désactivé.")

        # ── Mise à jour state ─────────────────────────────────────────────────
        now_iso = datetime.now(timezone.utc).isoformat()
        for item in new_cves:
            entry: dict = notified.setdefault(item["id"], {})
            entry["severity"] = item.get("severity", "UNKNOWN")
            entry["cvss"] = item.get("cvss")
            entry["detected_at"] = item.get("detected_at", now_iso)
            if item in to_notify:
                if telegram_sent > 0:
                    entry["telegram_at"] = now_iso
                if email_sent > 0:
                    entry["email_at"] = now_iso

        state["notified"] = notified
        state["last_successful_run"] = now_iso
        save_state(state)

    elif not new_cves and not SEND_EMPTY_REPORT:
        # Pas de nouvelles CVE, pas de rapport vide demandé
        # On met quand même à jour last_successful_run
        state["last_successful_run"] = datetime.now(timezone.utc).isoformat()
        save_state(state)

    # ── Résumé final ──────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("Collecte terminée avec succès.")
    logger.info("  Nouvelles CVE      : %d", len(new_cves))
    logger.info("  Dashboard total    : %d", len(all_cves))
    logger.info("  Notifications envoyées (Telegram) : %d", telegram_sent)
    logger.info("  Notifications envoyées (Email)    : %d", email_sent)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
