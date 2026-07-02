import time
import requests

from utils.network_utils import get_domain, get_ip_address, get_ssl_info
from utils.dns_utils import get_dns_records, get_dmarc_record

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


def analyze_website(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        start_time = time.time()
        response = requests.get(url, timeout=5)
        end_time = time.time()

        response_time_ms = round((end_time - start_time) * 1000)

        final_url = response.url
        headers = response.headers
        cookie_report = []
        score = 0
        findings = []
        header_report = {}
        for cookie in response.cookies:
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
            score += 20
            findings.append(
                "Risky HTTP methods exposed: " + ", ".join(detected_risky_methods)
            )

            methods_rating = "Weak"
            methods_recommendation = "Disable risky HTTP methods such as PUT, DELETE, or TRACE unless strictly required."
        else:
            methods_rating = "Good"
            methods_recommendation = "No risky HTTP methods were detected."
        domain = get_domain(final_url)
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
        if not spf_found:
            score += 8
            findings.append("SPF record was not found. Email spoofing protection may be weak.")

        if not dmarc_found:
            score += 10
            findings.append("DMARC record was not found. Domain may be more vulnerable to email spoofing.")
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
                            disallowed_paths.append(path)

        except requests.exceptions.RequestException:
            robots_found = False
        if robots_found:
            robots_rating = "Informational"
            robots_recommendation = "Review exposed disallowed paths and avoid listing sensitive admin or private routes."
        else:
            robots_rating = "Informational"
            robots_recommendation = "robots.txt was not found. This is not necessarily a security issue."

        robots_description = "robots.txt tells search engine crawlers which paths they should avoid crawling."

        security_txt_url = final_url.rstrip("/") + "/.well-known/security.txt"
        security_txt_found = False

        try:
            security_txt_response = requests.get(security_txt_url, timeout=5)

            if security_txt_response.status_code == 200:
                security_txt_found = True

        except requests.exceptions.RequestException:
            security_txt_found = False
        if security_txt_found:
            security_txt_rating = "Good"
            security_txt_recommendation = "security.txt was found. The site provides a vulnerability disclosure contact path."
        else:
            security_txt_rating = "Informational"
            security_txt_recommendation = "Consider adding security.txt to provide vulnerability reporting information."

        security_txt_description = "security.txt helps security researchers report vulnerabilities responsibly."

        if not https_enabled:
            score += 25
            findings.append("Website does not use HTTPS.")

        if not ssl_info["certificate_valid"]:
            score += 25
            findings.append("SSL certificate is invalid or unavailable.")
        days_remaining = ssl_info.get("days_remaining")

        if days_remaining is not None:
            if days_remaining <= 0:
                score += 25
                findings.append("SSL certificate has expired.")
            elif days_remaining <= 15:
                score += 15
                findings.append("SSL certificate expires very soon.")
            elif days_remaining <= 30:
                score += 8
                findings.append("SSL certificate expires within 30 days.")
        
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

        if score >= 60:
            risk_level = "High Risk"
        elif score >= 30:
            risk_level = "Moderate Risk"
        else:
            risk_level = "Low Risk"

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
            "security_headers": header_report,
            "cookies": cookie_report,
            "dns": {
                "records": dns_records,
                "dmarc": dmarc_record,
                "spf_found": spf_found,
                "dmarc_found": dmarc_found
            },
            "http_methods": {
                "allowed_methods": allowed_methods,
                "risky_methods": detected_risky_methods,
                "security_rating": methods_rating,
                "recommendation": methods_recommendation
            },
            "robots_txt": {
                "found": robots_found,
                "disallowed_paths": disallowed_paths,
                "security_rating": robots_rating,
                "description": robots_description,
                "recommendation": robots_recommendation
            },
            "security_txt": {
                "found": security_txt_found,
                "url": security_txt_url,
                "security_rating": security_txt_rating,
                "description": security_txt_description,
                "recommendation": security_txt_recommendation
            },
            "summary": {
                "score": score,
                "risk_level": risk_level,
                "findings": findings
            }
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
            "security_headers": {},
            "cookies": [],
            "dns": {
                "records": {},
                "dmarc": [],
                "spf_found": False,
                "dmarc_found": False
            },
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
            "summary": {
                "score": 100,
                "risk_level": "High Risk",
                "findings": ["Unable to reach website."]
            }
        }