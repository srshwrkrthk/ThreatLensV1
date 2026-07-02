import requests


def analyze_website(url: str):
    findings = []
    score = 0

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if not url.startswith("https://"):
            score += 25
            findings.append("Website does not use HTTPS.")

        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header.",
            "Content-Security-Policy": "Missing Content Security Policy header.",
            "X-Frame-Options": "Missing X-Frame-Options header.",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header.",
        }

        for header, message in security_headers.items():
            if header not in headers:
                score += 15
                findings.append(message)

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

    except requests.exceptions.RequestException:
        return {
            "score": 100,
            "risk_level": "High Risk",
            "findings": ["Unable to reach website."]
        }