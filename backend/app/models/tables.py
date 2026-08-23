from sqlalchemy import Table, Column, Integer, String, DateTime, ForeignKey, Boolean, JSON, Float, func
from app.database import metadata

logs_table = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime(timezone=True), server_default=func.now(), index=True),
    Column("source_ip", String, index=True),
    Column("destination_ip", String),
    Column("event_type", String, index=True),  # e.g., login_failed, firewall_block, connection
    Column("severity", String),                # Low, Medium, High, Critical
    Column("raw_message", String),
    Column("parsed_data", JSON, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

threat_alerts_table = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("log_id", Integer, ForeignKey("logs.id"), nullable=True),
    Column("threat_type", String, index=True),
    Column("threat_score", Float),
    Column("description", String),
    Column("is_resolved", Boolean, default=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)