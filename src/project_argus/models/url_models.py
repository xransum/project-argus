"""URL models for Project Argus API"""

from typing import Dict, Optional

from pydantic import BaseModel


class URLStatusResponse(BaseModel):
    url: str
    status_code: int
    is_reachable: bool
    response_time_ms: float
    error: Optional[str] = None


class URLHeadersResponse(BaseModel):
    url: str
    headers: Dict[str, str]
    status_code: int
