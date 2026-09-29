from datetime import datetime, timezone

from .config import (
    KEYWORDS,
    MAX_CVES,
    MIN_CVSS,
    SEND_EMPTY_REPORT,
)
from .nvd import fetch_recent
from .cisa import fetch_kev
from .scoring import get_cvss, severity_from_score
from .database import (
    ensure_data,
    load_cves,
    save_cves,
    load_state,
    save_state,
    save_stats,
)
from .telegram import send as telegram_send, enabled as telegram_enabled
from .email import send as email_send, enabled as email_enabled


def description(cve):
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    return descriptions[0].get("value", "") if descriptions else ""


def affected_products(cve):
    products = []

    for node in cve.get("configurations", []):
        for node_item in node.get("nodes", []):
            for match in node_item.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    products.append(criteria)

    return products[:20]


def matches_keywords(cve_id, text):
    if not KEYWORDS:
        return True

    haystack = f"{cve_id} {text}".lower()
    return any(keyword in haystack for keyword in KEYWORDS)


def normalize(cve, kev):
    cve_id = cve["id"]
    score, base_severity = get_cvss(cve)
    severity = severity_from_score(score)

    kev_item = kev.get(cve_id)

    published = cve.get("published")
    modified = cve.get("lastModified")

    return {
        "id": cve_id,
        "published": published,
        "modified": modified,
        "description": description(cve),
        "cvss": score,
        "severity": severity if severity != "UNKNOWN" else base_severity,
        "kev": bool(kev_item),
        "vendor": kev_item.get("vendorProject", "") if kev_item else "",
        "product": kev_item.get("product", "") if kev_item else "",
        "kev_date": kev_item.get("dateAdded", "") if kev_item else "",
        "ransomware": kev_item.get("knownRansomwareCampaignUse", "") if kev_item else "",
        "due_date": kev_item.get("dueDate", "") if kev_item else "",
        "products": affected_products(cve),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def alert_block(item):
    kev = "⚠️ CISA KEV — EXPLOITED" if item["kev"] else "ℹ️ Not listed in CISA KEV"

    score = item["cvss"]
    score_text = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"

    text = " ".join(item["description"].split())

    if len(text) > 450:
        text = text[:447] + "..."

    return (
        f"🔴 {item['id']}\n"
        f"📊 CVSS: {score_text} — {item['severity']}\n"
        f"{kev}\n"
        f"📝 {text}\n"
        f"🔗 {item['url']}"
    )


def build_messages(items):
    header = (
        f"🛡️ CVE SENTINEL\n"
        f"📅 {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n"
        f"🚨 {len(items)} new vulnerability alert(s)\n\n"
    )

    messages = []
    current = header

    for item in items:
        block = alert_block(item)

        if len(current) + len(block) + 3 > 3800:
            messages.append(current)
            current = block
        else:
            current += block + "\n\n"

    if current:
        messages.append(current)

    return messages


def main():
    ensure_data()

    print("Collecting NVD...")
    raw = fetch_recent()

    print("Collecting CISA KEV...")
    kev = fetch_kev()

    state = load_state()
    sent = set(state.get("sent", []))

    fresh = []

    for wrapper in raw:
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id")

        if not cve_id or cve_id in sent:
            continue

        text = description(cve)
        score, _ = get_cvss(cve)

        if score is None and MIN_CVSS > 0:
            continue

        if score is not None and score < MIN_CVSS:
            continue

        if not matches_keywords(cve_id, text):
            continue

        fresh.append(normalize(cve, kev))

    fresh.sort(
        key=lambda x: (
            x["kev"],
            x["cvss"] if x["cvss"] is not None else -1,
        ),
        reverse=True,
    )

    fresh = fresh[:MAX_CVES]

    # Keep a rolling dashboard history.
    existing = {
        item["id"]: item
        for item in load_cves()
    }

    for item in fresh:
        existing[item["id"]] = item

    all_cves = list(existing.values())
    all_cves.sort(
        key=lambda x: x.get("published") or "",
        reverse=True,
    )

    # Keep the public dashboard compact.
    all_cves = all_cves[:5000]

    save_cves(all_cves)
    save_stats(all_cves)

    if fresh:
        for message in build_messages(fresh):
            if telegram_enabled():
                telegram_send(message)

        email_body = "\n\n".join(
            alert_block(item) for item in fresh
        )

        if email_enabled():
            email_send(
                f"CVE Sentinel — {len(fresh)} new CVE(s)",
                email_body,
            )

        sent.update(item["id"] for item in fresh)
        state["sent"] = list(sent)[-10000:]
        save_state(state)

    elif SEND_EMPTY_REPORT:
        empty = (
            "🛡️ CVE SENTINEL\n\n"
            "No new CVE matched the configured filters."
        )

        if telegram_enabled():
            telegram_send(empty)

        if email_enabled():
            email_send("CVE Sentinel — no new matching CVE", empty)

    print(f"New matching CVEs: {len(fresh)}")
    print(f"Dashboard history: {len(all_cves)} CVEs")


if __name__ == "__main__":
    main()
