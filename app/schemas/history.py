from __future__ import annotations
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from app.domain.enums import RiskLabel, AnalysisType

class HistoryItemOut(BaseModel):
    id: str
    created_at: datetime
    analysis_type: AnalysisType
    label: RiskLabel
    status: str
    source: Optional[str] = None 

class HistoryPageOut(BaseModel):
    items: List[HistoryItemOut]
    page: int
    page_size: int
    total: int
    total_pages: int

class HistoryFiltersIn(BaseModel):
    page: int = 1
    page_size: int = 6
    q: Optional[str] = None               
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    status: Optional[RiskLabel] = None     
    analysis_type: Optional[AnalysisType] = None
    
class HistoryDetailOut(BaseModel):
    id: str
    created_at: datetime
    analysis_type: AnalysisType
    label: RiskLabel
    status: str
    source: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_recommendations: list[str] = []
    ai_raw: Optional[str] = None 
