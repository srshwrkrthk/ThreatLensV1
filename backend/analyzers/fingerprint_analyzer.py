def detect_technologies(headers, html: str):
    detected = []

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server:
        detected.append({
            "name": server,
            "category": "Server",
            "evidence": "Server header",
            "confidence": "High"
        })

    if powered_by:
        detected.append({
            "name": powered_by,
            "category": "Backend",
            "evidence": "X-Powered-By header",
            "confidence": "High"
        })

    html_lower = html.lower()

    fingerprints = [
        {
            "name": "React",
            "category": "Frontend Framework",
            "patterns": ["react", "react-dom"],
        },
        {
            "name": "Next.js",
            "category": "Frontend Framework",
            "patterns": ["_next/", "__next"],
        },
        {
            "name": "Vue.js",
            "category": "Frontend Framework",
            "patterns": ["vue.js", "__vue__"],
        },
        {
            "name": "Angular",
            "category": "Frontend Framework",
            "patterns": ["ng-version", "angular"],
        },
        {
            "name": "WordPress",
            "category": "CMS",
            "patterns": ["wp-content", "wp-includes", "wordpress"],
        },
        {
            "name": "Bootstrap",
            "category": "CSS Framework",
            "patterns": ["bootstrap"],
        },
        {
            "name": "jQuery",
            "category": "JavaScript Library",
            "patterns": ["jquery"],
        },
        {
            "name": "Cloudflare",
            "category": "CDN / Security",
            "patterns": ["cloudflare", "cf-ray"],
        }
    ]

    for tech in fingerprints:
        if any(pattern in html_lower for pattern in tech["patterns"]):
            detected.append({
                "name": tech["name"],
                "category": tech["category"],
                "evidence": "HTML pattern match",
                "confidence": "Medium"
            })

    return detected