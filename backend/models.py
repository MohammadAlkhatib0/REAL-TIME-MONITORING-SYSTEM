from datetime import datetime
from sqlalchemy import (
    Table, Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, func
)
from .database import metadata, Base

# --- 1. SQLAlchemy Core Table Schemas (Step 5 & 6) ---
logs_table = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime(timezone=True), nullable=False, default=datetime.utcnow),
    Column("source_ip", String(45), nullable=False, index=True),
    Column("destination_ip", String(45), nullable=False),
    Column("event_type", String(50), nullable=False, index=True),
    Column("severity", String(20), nullable=False, index=True),
    Column("raw_message", Text, nullable=True),
    Column("parsed_data", JSON, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

threat_alerts_table = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("log_id", Integer, ForeignKey("logs.id", ondelete="SET NULL"), nullable=True),
    Column("threat_type", String(50), nullable=False, index=True),
    Column("threat_score", Float, nullable=False, default=0.0),
    Column("description", Text, nullable=False),
    Column("is_resolved", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

# --- 2. ORM Models ---
class Log(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10), index=True)
    action = Column(String(10), index=True)  # ALLOW, BLOCK, FLAG
    bytes_transferred = Column(Integer, default=0)
    message = Column(Text, nullable=True)

class Alert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    log_id = Column(Integer, ForeignKey("network_logs.id"), nullable=True)
    severity = Column(String(20), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    rule_name = Column(String(50), index=True)
    source_ip = Column(String(45), index=True)
    description = Column(Text)
    status = Column(String(20), default="ACTIVE")  # ACTIVE, ACKNOWLEDGED, RESOLVED

class MetricSnapshot(Base):
    __tablename__ = "metrics_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    throughput_lps = Column(Float)
    active_alerts_count = Column(Integer)
    bandwidth_kbps = Column(Float)
