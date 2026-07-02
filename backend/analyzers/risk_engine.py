def get_risk_level(score: int):
    if score >= 60:
        return "High Risk"
    elif score >= 30:
        return "Moderate Risk"
    else:
        return "Low Risk"


def calculate_website_risk(risk_points: list):
    total_score = sum(item["points"] for item in risk_points)

    findings = [
        item["message"]
        for item in risk_points
        if item["points"] > 0
    ]

    return {
        "score": total_score,
        "risk_level": get_risk_level(total_score),
        "findings": findings
    }


def calculate_overall_risk(password_score: int, url_score: int, website_score: int):
    overall_score = round(
        (password_score * 0.25) +
        (url_score * 0.30) +
        (website_score * 0.45)
    )

    return {
        "overall_score": overall_score,
        "risk_level": get_risk_level(overall_score),
        "components": {
            "password_score": password_score,
            "url_score": url_score,
            "website_score": website_score
        },
        "weights": {
            "password": "25%",
            "url": "30%",
            "website": "45%"
        }
    }