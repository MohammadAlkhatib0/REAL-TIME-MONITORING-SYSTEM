from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict

class LogCreate(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    action: str
    bytes_transferred: int = 0
    message: Optional[str] = ""

class LogResponse(LogCreate):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertCreate(BaseModel):
    timestamp: Optional[datetime] = None
    log_id: Optional[int] = None
    severity: str
    rule_name: str
    source_ip: str
    description: str
    status: str = "ACTIVE"

class AlertResponse(AlertCreate):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class MetricSnapshotResponse(BaseModel):
    id: Optional[int] = None
    timestamp: datetime
    throughput_lps: float
    active_alerts_count: int
    bandwidth_kbps: float

    model_config = ConfigDict(from_attributes=True)

class WebSocketMessage(BaseModel):
    type: str  # "LOG", "ALERT", "METRICS", "INITIAL_STATE"
    payload: Any
