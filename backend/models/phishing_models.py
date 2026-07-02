from pydantic import BaseModel
from typing import List


class URLRequest(BaseModel):
    url: str


class URLResponse(BaseModel):
    score: int
    risk_level: str
    findings: List[str]