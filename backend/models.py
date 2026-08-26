from datetime import datetime
from sqlalchemy import (
    Table, Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, func
)
from .database import metadata

# --- SQLAlchemy Core Table Schemas ---

logs_table = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True),
    Column("source_ip", String(45), nullable=False, index=True),
    Column("destination_ip", String(45), nullable=False),
    Column("source_port", Integer, nullable=True, default=0),
    Column("destination_port", Integer, nullable=True, default=80),
    Column("protocol", String(10), nullable=True, default="TCP", index=True),
    Column("action", String(10), nullable=True, default="ALLOW", index=True),
    Column("event_type", String(50), nullable=True, default="connection", index=True),
    Column("severity", String(20), nullable=True, default="LOW", index=True),
    Column("bytes_transferred", Integer, nullable=True, default=0),
    Column("message", Text, nullable=True),
    Column("raw_message", Text, nullable=True),
    Column("parsed_data", JSON, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

threat_alerts_table = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True),
    Column("log_id", Integer, ForeignKey("logs.id", ondelete="SET NULL"), nullable=True),
    Column("rule_name", String(50), nullable=True, index=True),
    Column("threat_type", String(50), nullable=True, index=True),
    Column("threat_score", Float, nullable=False, default=0.0),
    Column("severity", String(20), nullable=False, default="MEDIUM", index=True),
    Column("source_ip", String(45), nullable=True, index=True),
    Column("description", Text, nullable=False),
    Column("status", String(20), nullable=False, default="ACTIVE", index=True),
    Column("is_resolved", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False)
)

metrics_snapshots_table = Table(
    "metrics_snapshots",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True),
    Column("throughput_lps", Float, nullable=False, default=0.0),
    Column("active_alerts_count", Integer, nullable=False, default=0),
    Column("bandwidth_kbps", Float, nullable=False, default=0.0)
)

blacklisted_ips_table = Table(
    "blacklisted_ips",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip_address", String(45), nullable=False, unique=True, index=True),
    Column("danger_level", String(20), nullable=False, default="HIGH", index=True),
    Column("reason", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False)
)
