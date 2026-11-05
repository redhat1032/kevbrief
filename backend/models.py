from pydantic import BaseModel
from typing import List, Optional

class ThreatItem(BaseModel):
    title: str
    published_date: str
    source: str
    tags: List[str]
    description: str
    link: str
    cves: Optional[List[str]] = []
    severity: Optional[str] = "Unknown" 

class ThreatResponse(BaseModel):
    threats: List[ThreatItem]
    total: int

class Stats(BaseModel):
    total_threats: int
    critical_count: int
    ransomware_count: int
    sources_count: int
