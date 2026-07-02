import time
import requests

from utils.network_utils import get_domain, get_ip_address, get_ssl_info
from utils.dns_utils import get_dns_records, get_dmarc_record
from analyzers.fingerprint_analyzer import detect_technologies
from analyzers.risk_engine import calculate_website_risk
from utils.whois_utils import get_whois_info


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces browsers to use HTTPS instead of HTTP.",
        "risk_impact": "Without HSTS, users may be vulnerable to protocol downgrade attacks.",
        "recommendation": "Enable HSTS to protect users from protocol downgrade attacks."
    },
    "Content-Security-Policy": {
        "description": "Helps prevent Cross-Site Scripting attacks.",
        "risk_impact": "Without CSP, injected scripts may run more easily in the browser.",
        "recommendation": "Add a CSP header to control which resources can load."
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks.",
        "risk_impact": "Without this header, attackers may embed the site in hidden iframes.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "description": "Prevents browsers from MIME-sniffing files.",
        "risk_impact": "Without this header, browsers may incorrectly interpret file types.",
        "recommendation": "Set X-Content-Type-Options to nosniff."
    }
}


def normalize_url(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url
    return url


def fetch_website(url: str):
    start_time = time.time()
    response = requests.get(url, timeout=5)
    end_time = time.time()

    response_time_ms = round((end_time - start_time) * 1000)

    return response, response_time_ms


def analyze_security_headers(headers):
    score = 0
    findings = []
    header_report = {}

    for header, info in SECURITY_HEADERS.items():
        if header in headers:
            header_report[header] = {
                "present": True,
                "value": headers[header],
                "security_rating": "Good",
                "description": info["description"],
                "risk_impact": info["risk_impact"],
                "recommendation": "No action needed."
            }
        else:
            score += 15
            findings.append(f"Missing {header} header.")
            header_report[header] = {
                "present": False,
                "value": None,
                "security_rating": "Critical",
                "description": info["description"],
                "risk_impact": info["risk_impact"],
                "recommendation": info["recommendation"]
            }

    return header_report, score, findings


def analyze_cookies(cookies):
    score = 0
    findings = []
    cookie_report = []

    for cookie in cookies:
        secure = cookie.secure
        httponly = "HttpOnly" in str(cookie._rest)
        samesite = cookie._rest.get("SameSite")

        missing_flags = []

        if not secure:
            missing_flags.append("Secure")

        if not httponly:
            missing_flags.append("HttpOnly")

        if not samesite:
            missing_flags.append("SameSite")

        if len(missing_flags) == 0:
            security_rating = "Good"
            recommendation = "Cookie security flags are properly configured."
        else:
            security_rating = "Weak"
            recommendation = "Add missing cookie flags: " + ", ".join(missing_flags)

            if "HttpOnly" in missing_flags:
                score += 5
                findings.append(f"Cookie '{cookie.name}' is missing HttpOnly flag.")

            if "Secure" in missing_flags:
                score += 10
                findings.append(f"Cookie '{cookie.name}' is missing Secure flag.")

            if "SameSite" in missing_flags:
                score += 5
                findings.append(f"Cookie '{cookie.name}' is missing SameSite flag.")

        cookie_report.append({
            "name": cookie.name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "security_rating": security_rating,
            "recommendation": recommendation
        })

    return cookie_report, score, findings


def analyze_http_methods(final_url: str):
    risky_methods = ["PUT", "DELETE", "TRACE"]
    allowed_methods = []

    try:
        options_response = requests.options(final_url, timeout=5)
        allow_header = options_response.headers.get("Allow", "")

        if allow_header:
            allowed_methods = [
                method.strip().upper()
                for method in allow_header.split(",")
            ]

    except requests.exceptions.RequestException:
        allowed_methods = []

    detected_risky_methods = [
        method for method in allowed_methods
        if method in risky_methods
    ]

    if detected_risky_methods:
        return {
            "allowed_methods": allowed_methods,
            "risky_methods": detected_risky_methods,
            "security_rating": "Weak",
            "recommendation": "Disable risky HTTP methods such as PUT, DELETE, or TRACE unless strictly required."
        }, 20, [
            "Risky HTTP methods exposed: " + ", ".join(detected_risky_methods)
        ]

    return {
        "allowed_methods": allowed_methods,
        "risky_methods": [],
        "security_rating": "Good",
        "recommendation": "No risky HTTP methods were detected."
    }, 0, []


def analyze_robots_txt(final_url: str):
    robots_url = final_url.rstrip("/") + "/robots.txt"
    robots_found = False
    disallowed_paths = []

    try:
        robots_response = requests.get(robots_url, timeout=5)

        if robots_response.status_code == 200:
            robots_found = True

            for line in robots_response.text.splitlines():
                line = line.strip()

                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()

                    if path:
                        if path not in disallowed_paths:
                            disallowed_paths.append(path)

    except requests.exceptions.RequestException:
        robots_found = False

    return {
        "found": robots_found,
        "disallowed_paths": disallowed_paths,
        "security_rating": "Informational",
        "description": "robots.txt tells search engine crawlers which paths they should avoid crawling.",
        "recommendation": (
            "Review exposed disallowed paths and avoid listing sensitive admin or private routes."
            if robots_found
            else "robots.txt was not found. This is not necessarily a security issue."
        )
    }


def analyze_security_txt(final_url: str):
    security_txt_url = final_url.rstrip("/") + "/.well-known/security.txt"
    security_txt_found = False

    try:
        security_txt_response = requests.get(security_txt_url, timeout=5)

        if security_txt_response.status_code == 200:
            security_txt_found = True

    except requests.exceptions.RequestException:
        security_txt_found = False

    return {
        "found": security_txt_found,
        "url": security_txt_url,
        "security_rating": "Good" if security_txt_found else "Informational",
        "description": "security.txt helps security researchers report vulnerabilities responsibly.",
        "recommendation": (
            "security.txt was found. The site provides a vulnerability disclosure contact path."
            if security_txt_found
            else "Consider adding security.txt to provide vulnerability reporting information."
        )
    }


def analyze_website(url: str):
    url = normalize_url(url)

    try:
        response, response_time_ms = fetch_website(url)

        final_url = response.url
        headers = response.headers
        technologies = detect_technologies(headers, response.text)
        domain = get_domain(final_url)
        whois_info = get_whois_info(domain)
        ip_address = get_ip_address(domain)

        dns_records = get_dns_records(domain)
        dmarc_record = get_dmarc_record(domain)

        txt_records = dns_records.get("TXT", [])
        spf_found = any("v=spf1" in record.lower() for record in txt_records)
        dmarc_found = len(dmarc_record) > 0

        https_enabled = final_url.startswith("https://")
        redirected = url != final_url
        server = headers.get("Server", "Not disclosed")

        ssl_info = get_ssl_info(domain) if https_enabled else {
            "issuer": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "certificate_valid": False
        }

        risk_points = []

        if not https_enabled:
            risk_points.append({
                "points": 25,
                "message": "Website does not use HTTPS."
            })

        if not ssl_info["certificate_valid"]:
            risk_points.append({
                "points": 25,
                "message": "SSL certificate is invalid or unavailable."
            })

        days_remaining = ssl_info.get("days_remaining")

        if days_remaining is not None:
            if days_remaining <= 0:
                risk_points.append({
                    "points": 25,
                    "message": "SSL certificate has expired."
                })
            elif days_remaining <= 15:
                risk_points.append({
                    "points": 15,
                    "message": "SSL certificate expires very soon."
                })
            elif days_remaining <= 30:
                risk_points.append({
                    "points": 8,
                    "message": "SSL certificate expires within 30 days."
                })

        if not spf_found:
            risk_points.append({
                "points": 8,
                "message": "SPF record was not detected in returned TXT records."
            })

        if not dmarc_found:
            risk_points.append({
                "points": 10,
                "message": "DMARC record was not found. Domain may be more vulnerable to email spoofing."
            })

        header_report, header_score, header_findings = analyze_security_headers(headers)
        for finding in header_findings:
            risk_points.append({
                "points": 15,
                "message": finding
            })

        cookie_report, cookie_score, cookie_findings = analyze_cookies(response.cookies)
        for finding in cookie_findings:
            risk_points.append({
                "points": 5,
                "message": finding
            })

        http_methods, methods_score, methods_findings = analyze_http_methods(final_url)
        for finding in methods_findings:
            risk_points.append({
                "points": methods_score,
                "message": finding
            })

        robots_txt = analyze_robots_txt(final_url)
        security_txt = analyze_security_txt(final_url)

        summary = calculate_website_risk(risk_points)

        return {
            "website": {
                "input_url": url,
                "final_url": final_url,
                "domain": domain,
                "ip_address": ip_address,
                "status_code": response.status_code,
                "https_enabled": https_enabled,
                "redirected": redirected,
                "server": server,
                "response_time_ms": response_time_ms
            },
            "ssl": ssl_info,
            "dns": {
                "records": dns_records,
                "dmarc": dmarc_record,
                "spf_found": spf_found,
                "dmarc_found": dmarc_found
            },
            "security_headers": header_report,
            "cookies": cookie_report,
            "http_methods": http_methods,
            "robots_txt": robots_txt,
            "security_txt": security_txt,
            "technologies": technologies,
            "whois": whois_info,
            "summary": summary
        }

    except requests.exceptions.RequestException:
        return {
            "website": {
                "input_url": url,
                "final_url": None,
                "domain": None,
                "ip_address": None,
                "status_code": None,
                "https_enabled": False,
                "redirected": False,
                "server": None,
                "response_time_ms": None
            },
            "ssl": {
                "issuer": None,
                "valid_from": None,
                "valid_until": None,
                "days_remaining": None,
                "certificate_valid": False
            },
            "dns": {
                "records": {},
                "dmarc": [],
                "spf_found": False,
                "dmarc_found": False
            },
            "security_headers": {},
            "cookies": [],
            "http_methods": {
                "allowed_methods": [],
                "risky_methods": [],
                "security_rating": "Unknown",
                "recommendation": "Unable to determine allowed HTTP methods."
            },
            "robots_txt": {
                "found": False,
                "disallowed_paths": [],
                "security_rating": "Unknown",
                "description": "robots.txt tells search engine crawlers which paths they should avoid crawling.",
                "recommendation": "Unable to check robots.txt."
            },
            "security_txt": {
                "found": False,
                "url": "",
                "security_rating": "Unknown",
                "description": "security.txt helps security researchers report vulnerabilities responsibly.",
                "recommendation": "Unable to check security.txt."
            },
            "technologies": [],
            "whois": {
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "name_servers": [],
                "emails": [],
                "country": None
            },
            "summary": {
                "score": 100,
                "risk_level": "High Risk",
                "findings": ["Unable to reach website."]
            }
        }