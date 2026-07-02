from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ThreatLens API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "ThreatLens API is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "threatlens-api"
    }


@app.post("/check-password")
def check_password(data: dict):
    password = data.get("password", "")

    score = 0
    findings = []

    if len(password) >= 8:
        score += 25
    else:
        findings.append("Password should be at least 8 characters long.")

    if any(ch.isupper() for ch in password):
        score += 20
    else:
        findings.append("Add at least one uppercase letter.")

    if any(ch.islower() for ch in password):
        score += 20
    else:
        findings.append("Add at least one lowercase letter.")

    if any(ch.isdigit() for ch in password):
        score += 20
    else:
        findings.append("Add at least one number.")

    if any(not ch.isalnum() for ch in password):
        score += 15
    else:
        findings.append("Add at least one symbol.")

    if score >= 80:
        risk_level = "Low Risk"
    elif score >= 50:
        risk_level = "Moderate Risk"
    else:
        risk_level = "High Risk"

    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings
    }