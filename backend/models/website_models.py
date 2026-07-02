from pydantic import BaseModel
from typing import List, Optional


class WebsiteRequest(BaseModel):
    url: str


class WebsiteResponse(BaseModel):
    url: str
    final_url: Optional[str]
    status_code: Optional[int]
    https_enabled: bool
    present_headers: List[str]
    missing_headers: List[str]
    robots_txt_found: bool
    security_txt_found: bool
    allowed_methods: str
    score: int
    risk_level: str
    findings: List[str]