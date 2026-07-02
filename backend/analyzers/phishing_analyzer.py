from urllib.parse import urlparse


def analyze_url(url: str):
    score = 0
    findings = []

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if parsed_url.scheme != "https":
        score += 25
        findings.append("URL does not use HTTPS.")

    if any(ch.isdigit() for ch in domain):
        score += 15
        findings.append("Domain contains numbers.")

    if "-" in domain:
        score += 15
        findings.append("Domain contains hyphens.")

    if len(url) > 75:
        score += 20
        findings.append("URL is unusually long.")

    suspicious_words = ["login", "verify", "update", "secure", "account", "bank"]

    if any(word in url.lower() for word in suspicious_words):
        score += 25
        findings.append("URL contains suspicious keywords.")

    if score >= 60:
        risk_level = "High Risk"
    elif score >= 30:
        risk_level = "Moderate Risk"
    else:
        risk_level = "Low Risk"

    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings
    }