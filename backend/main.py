from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
#Instead of direct import, i am importing the PassWordreq from models here, this allows me to make multiple requests instead of fixed one
from models.password_models import PasswordRequest, PasswordResponse
from analyzers.password_analyzer import analyze_password
from analyzers.phishing_analyzer import analyze_url
from models.phishing_models import URLRequest, URLResponse

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


@app.post("/check-password", response_model=PasswordResponse)
def check_password(data: PasswordRequest):
    return analyze_password(data.password)

@app.post("/analyze-url", response_model=URLResponse)
def check_url(data: URLRequest):
    return analyze_url(data.url)