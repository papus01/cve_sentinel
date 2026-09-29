def get_cvss(cve):
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if not entries:
            continue

        cvss = entries[0].get("cvssData", {})
        score = cvss.get("baseScore")

        if score is not None:
            return float(score), cvss.get("baseSeverity", "UNKNOWN").upper()

    return None, "UNKNOWN"


def severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"
