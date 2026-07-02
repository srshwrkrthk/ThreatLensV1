from pydantic import BaseModel
from typing import Dict, List, Optional


class WebsiteRequest(BaseModel):
    url: str


class WebsiteInfo(BaseModel):
    input_url: str
    final_url: Optional[str]
    domain: Optional[str]
    ip_address: Optional[str]
    status_code: Optional[int]
    https_enabled: bool
    redirected: bool
    server: Optional[str]
    response_time_ms: Optional[int]


class SSLInfo(BaseModel):
    issuer: Optional[str]
    valid_from: Optional[str]
    valid_until: Optional[str]
    days_remaining: Optional[int]
    certificate_valid: bool

class HeaderInfo(BaseModel):
    present: bool
    value: Optional[str]
    security_rating: str
    description: str
    risk_impact: str
    recommendation: str

class CookieInfo(BaseModel):
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]
    security_rating: str
    recommendation: str

class DNSInfo(BaseModel):
    records: Dict[str, List[str]]
    dmarc: List[str]
    spf_found: bool
    dmarc_found: bool

class HTTPMethodsInfo(BaseModel):
    allowed_methods: List[str]
    risky_methods: List[str]
    security_rating: str
    recommendation: str

class RobotsInfo(BaseModel):
    found: bool
    disallowed_paths: List[str]
    security_rating: str
    description: str
    recommendation: str

class SecurityTxtInfo(BaseModel):
    found: bool
    url: str
    security_rating: str
    description: str
    recommendation: str

class WebsiteSummary(BaseModel):
    score: int
    risk_level: str
    findings: List[str]

class WebsiteResponse(BaseModel):
    website: WebsiteInfo
    ssl: SSLInfo
    dns: DNSInfo
    security_headers: Dict[str, HeaderInfo]
    cookies: List[CookieInfo]
    http_methods: HTTPMethodsInfo
    robots_txt: RobotsInfo
    security_txt: SecurityTxtInfo
    summary: WebsiteSummary
