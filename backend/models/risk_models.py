from pydantic import BaseModel
from typing import Dict


class RiskRequest(BaseModel):
    password_score: int
    url_score: int
    website_score: int


class RiskResponse(BaseModel):
    overall_score: int
    risk_level: str
    components: Dict[str, int]
    weights: Dict[str, str]