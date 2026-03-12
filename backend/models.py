from pydantic import BaseModel
from typing import Optional


class AlertFilter(BaseModel):
    severity: Optional[str] = None
    agent: Optional[str] = None
    rule_group: Optional[str] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "ai_priority"


class SyncStatus(BaseModel):
    id: int = 1
    status: str = "idle"
    message: str = "Sin sincronizar"
    last_sync: Optional[str] = None
    total_processed: int = 0
