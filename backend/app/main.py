import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import insert, select, desc, update, func, text

from app.database import engine, metadata
from app.models.tables import logs_table, threat_alerts_table
from app.services.log_parser import LogParser
from app.services.threat_detector import ThreatDetector, BLACKLISTED_IPS

metadata.create_all(bind=engine)

app = FastAPI(title="Real-Time Threat Intelligence System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Real-Time Monitoring Endpoints ---

@app.post("/api/ingest/log")
async def ingest_log(raw_message: str):
    parsed = LogParser.parse_raw_log(raw_message)
    
    stmt = insert(logs_table).values(**parsed).returning(logs_table.c.id)
    with engine.connect() as conn:
        result = conn.execute(stmt)
        new_id = result.scalar()
        conn.commit()
    
    log_data = {
        "event": "new_log",
        "id": new_id,
        "source_ip": parsed["source_ip"],
        "event_type": parsed["event_type"],
        "severity": parsed["severity"]
    }
    await manager.broadcast(log_data)
    
    alert = ThreatDetector.analyze_log(
        log_id=new_id,
        source_ip=parsed["source_ip"],
        event_type=parsed["event_type"],
        severity=parsed["severity"]
    )
    
    if alert:
        alert_stmt = insert(threat_alerts_table).values(
            log_id=alert["log_id"],
            threat_type=alert["threat_type"],
            threat_score=alert["threat_score"],
            description=alert["description"],
            is_resolved=False
        ).returning(threat_alerts_table.c.id)
        
        with engine.connect() as conn:
            alert_id = conn.execute(alert_stmt).scalar()
            conn.commit()
            
        alert["id"] = alert_id
        await manager.broadcast({"event": "threat_alert", **alert})
    
    return {"status": "success", "log_id": new_id, "threat_detected": alert is not None}

@app.get("/api/logs/recent")
def get_recent_logs(limit: int = 50):
    stmt = select(logs_table).order_by(desc(logs_table.c.id)).limit(limit)
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [dict(row._mapping) for row in result]

# --- Threat Detection Endpoints ---

@app.get("/api/threats")
def get_threats(severity: Optional[str] = None, is_resolved: Optional[bool] = None, limit: int = 50):
    stmt = select(threat_alerts_table).order_by(desc(threat_alerts_table.c.id)).limit(limit)
    if is_resolved is not None:
        stmt = stmt.where(threat_alerts_table.c.is_resolved == is_resolved)
    with engine.connect() as conn:
        result = conn.execute(stmt)
        records = [dict(row._mapping) for row in result]
        if severity:
            records = [r for r in records if r.get("threat_score", 0) >= (81 if severity=="Critical" else 61 if severity=="High" else 31)]
        return records

@app.get("/api/threats/{threat_id}")
def get_threat_detail(threat_id: int):
    stmt = select(threat_alerts_table).where(threat_alerts_table.c.id == threat_id)
    with engine.connect() as conn:
        result = conn.execute(stmt).first()
        if not result:
            raise HTTPException(status_code=404, detail="Threat not found")
        return dict(result._mapping)

@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat(threat_id: int):
    stmt = (
        update(threat_alerts_table)
        .where(threat_alerts_table.c.id == threat_id)
        .values(is_resolved=True)
    )
    with engine.connect() as conn:
        conn.execute(stmt)
        conn.commit()
    return {"status": "success", "resolved_id": threat_id}

@app.get("/api/threats/stats")
def get_threat_stats():
    stmt = select(
        threat_alerts_table.c.threat_type,
        func.count(threat_alerts_table.c.id).label("count")
    ).group_by(threat_alerts_table.c.threat_type)
    
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [dict(row._mapping) for row in result]

# --- Analytics Endpoints ---

@app.get("/api/analytics/timeline")
def get_timeline():
    stmt = select(
        func.date_trunc('minute', logs_table.c.timestamp).label("time"),
        func.count(logs_table.c.id).label("log_count")
    ).group_by(text("1")).order_by(text("1 DESC")).limit(30)
    
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [{"time": str(row.time), "log_count": row.log_count} for row in result]

@app.get("/api/analytics/top-sources")
def get_top_sources(limit: int = 5):
    stmt = select(
        logs_table.c.source_ip,
        func.count(logs_table.c.id).label("count")
    ).group_by(logs_table.c.source_ip).order_by(desc(text("count"))).limit(limit)
    
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [dict(row._mapping) for row in result]

# --- IP Intelligence & pfSense Endpoints ---

@app.get("/api/ip/{ip_address}/info")
def get_ip_info(ip_address: str):
    is_blacklisted = ip_address in BLACKLISTED_IPS
    stmt = select(func.count(logs_table.c.id)).where(logs_table.c.source_ip == ip_address)
    with engine.connect() as conn:
        total_logs = conn.execute(stmt).scalar()
        
    return {
        "ip": ip_address,
        "is_blacklisted": is_blacklisted,
        "total_logs_count": total_logs
    }

@app.post("/api/ip/blacklist")
def add_to_blacklist(ip_address: str):
    BLACKLISTED_IPS.add(ip_address)
    return {"status": "success", "message": f"IP {ip_address} blacklisted successfully"}

@app.post("/api/ingest/pfsense")
async def ingest_pfsense(raw_message: str):
    return await ingest_log(raw_message)

@app.get("/api/pfsense/firewall-rules")
def get_pfsense_rules():
    stmt = select(
        logs_table.c.event_type,
        func.count(logs_table.c.id).label("hits")
    ).where(logs_table.c.event_type == "firewall_block").group_by(logs_table.c.event_type)
    
    with engine.connect() as conn:
        result = conn.execute(stmt)
        return [dict(row._mapping) for row in result]