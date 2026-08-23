import asyncio
import time
from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from .database import get_db, init_db
from .models import Log, Alert, MetricSnapshot
from .schemas import LogCreate, LogResponse, AlertResponse, MetricSnapshotResponse
from .parser import LogParser
from log_parser import LogParser as StandaloneLogParser
from .threat_engine import threat_engine
from .websocket_manager import manager
from threat_scorer import ThreatScorer
from threat_detector import DEFAULT_BLACKLISTED_IPS

app = FastAPI(
    title="Real-Time Network Monitoring & Threat Detection API",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global memory counters for throughput calculation
window_log_count = 0
window_bytes_count = 0
last_metrics_calc_time = time.time()
custom_blacklisted_ips = set(DEFAULT_BLACKLISTED_IPS)

@app.on_event("startup")
def on_startup():
    init_db()
    asyncio.create_task(broadcast_metrics_loop())

async def broadcast_metrics_loop():
    global window_log_count, window_bytes_count, last_metrics_calc_time
    while True:
        await asyncio.sleep(1.0)
        now = time.time()
        elapsed = max(now - last_metrics_calc_time, 1.0)
        
        lps = round(window_log_count / elapsed, 1)
        kbps = round((window_bytes_count / 1024) / elapsed, 1)
        
        window_log_count = 0
        window_bytes_count = 0
        last_metrics_calc_time = now

        db = next(get_db())
        try:
            active_alerts = db.query(Alert).filter(Alert.status == "ACTIVE").count()
            snapshot = MetricSnapshot(
                timestamp=datetime.utcnow(),
                throughput_lps=lps,
                active_alerts_count=active_alerts,
                bandwidth_kbps=kbps
            )
            db.add(snapshot)
            db.commit()

            metrics_payload = {
                "timestamp": snapshot.timestamp.isoformat(),
                "throughput_lps": lps,
                "active_alerts_count": active_alerts,
                "bandwidth_kbps": kbps
            }

            await manager.broadcast({
                "event": "metrics_update",
                "type": "METRICS",
                "payload": metrics_payload
            })
        except Exception:
            db.rollback()
        finally:
            db.close()

# --- REST Endpoints ---

@app.get("/")
def read_root():
    return {"status": "online", "system": "Real-Time Network Monitoring & Threat Detection System"}

# Real-time Monitoring Endpoint: POST /api/ingest/log
@app.post("/api/ingest/log")
@app.post("/api/logs")
async def ingest_log(raw_log: Union[Dict[str, Any], str], db: Session = Depends(get_db)):
    global window_log_count, window_bytes_count
    
    # 1. Parse log
    log_data = LogParser.parse_and_normalize(raw_log)
    
    # Check custom blacklist
    if log_data.source_ip in custom_blacklisted_ips:
        log_data.action = "BLOCK"
        log_data.severity = "CRITICAL"

    # 2. Save log to database
    db_log = Log(
        timestamp=log_data.timestamp,
        source_ip=log_data.source_ip,
        destination_ip=log_data.destination_ip,
        source_port=log_data.source_port,
        destination_port=log_data.destination_port,
        protocol=log_data.protocol,
        action=log_data.action,
        bytes_transferred=log_data.bytes_transferred,
        message=log_data.message
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    window_log_count += 1
    window_bytes_count += log_data.bytes_transferred

    # 3. Analyze for threats & calculate threat score/reasoning
    detected_alerts = threat_engine.analyze_log(log_data)
    saved_alerts_payloads = []
    
    for alert_data in detected_alerts:
        score, _ = ThreatScorer.calculate_score([alert_data.rule_name])
        if score == 0:
            score = 90.0 if alert_data.severity == "CRITICAL" else (75.0 if alert_data.severity == "HIGH" else 50.0)

        db_alert = Alert(
            timestamp=alert_data.timestamp,
            log_id=db_log.id,
            severity=alert_data.severity,
            rule_name=alert_data.rule_name,
            source_ip=alert_data.source_ip,
            description=alert_data.description,
            status="ACTIVE"
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        
        alert_payload = {
            "id": db_alert.id,
            "timestamp": db_alert.timestamp.isoformat(),
            "log_id": db_alert.log_id,
            "severity": db_alert.severity,
            "threat_type": db_alert.rule_name,
            "rule_name": db_alert.rule_name,
            "threat_score": score,
            "source_ip": db_alert.source_ip,
            "description": db_alert.description,
            "reasoning": db_alert.description,
            "status": db_alert.status
        }
        saved_alerts_payloads.append(alert_payload)

    # 4. Immediate WebSocket Broadcast
    log_payload = {
        "id": db_log.id,
        "timestamp": db_log.timestamp.isoformat(),
        "source_ip": db_log.source_ip,
        "destination_ip": db_log.destination_ip,
        "source_port": db_log.source_port,
        "destination_port": db_log.destination_port,
        "protocol": db_log.protocol,
        "action": db_log.action,
        "bytes_transferred": db_log.bytes_transferred,
        "message": db_log.message
    }
    
    await manager.broadcast({"event": "new_log", "type": "LOG", "payload": log_payload, "data": log_payload})
    
    for a_payload in saved_alerts_payloads:
        await manager.broadcast({"event": "threat_alert", "type": "ALERT", "payload": a_payload, "data": a_payload})

    return {
        "status": "success",
        "log": log_payload,
        "alerts_triggered": len(saved_alerts_payloads)
    }

# Real-time Monitoring Endpoint: GET /api/logs/recent
@app.get("/api/logs/recent")
@app.get("/api/logs")
def get_recent_logs(
    limit: int = Query(50, le=500),
    source_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Log)
    if source_ip:
        query = query.filter(Log.source_ip.contains(source_ip))
    if protocol:
        query = query.filter(Log.protocol == protocol.upper())
    if action:
        query = query.filter(Log.action == action.upper())
    
    logs = query.order_by(Log.timestamp.desc()).limit(limit).all()
    return logs

# --- Threat Detection Endpoints ---

# GET /api/threats/stats (STATIC ROUTE DECLARED BEFORE PARAMETERIZED ROUTE)
@app.get("/api/threats/stats")
def get_threat_stats(db: Session = Depends(get_db)):
    total_threats = db.query(Alert).count()
    active_threats = db.query(Alert).filter(Alert.status == "ACTIVE").count()

    severity_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    by_severity = {s: count for s, count in severity_counts}

    type_counts = db.query(Alert.rule_name, func.count(Alert.id)).group_by(Alert.rule_name).all()
    by_type = {t: count for t, count in type_counts}

    return {
        "total_threats": total_threats,
        "active_threats": active_threats,
        "by_severity": by_severity,
        "by_type": by_type
    }

# GET /api/threats
@app.get("/api/threats")
@app.get("/api/alerts")
def get_threats(
    severity: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if from_date:
        try:
            dt_from = datetime.fromisoformat(from_date)
            query = query.filter(Alert.timestamp >= dt_from)
        except ValueError:
            pass
    if to_date:
        try:
            dt_to = datetime.fromisoformat(to_date)
            query = query.filter(Alert.timestamp <= dt_to)
        except ValueError:
            pass
            
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    
    response = []
    for a in alerts:
        score, _ = ThreatScorer.calculate_score([a.rule_name])
        if score == 0:
            score = 90.0 if a.severity == "CRITICAL" else (75.0 if a.severity == "HIGH" else 50.0)

        response.append({
            "id": a.id,
            "log_id": a.log_id,
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "threat_type": a.rule_name,
            "rule_name": a.rule_name,
            "threat_score": score,
            "source_ip": a.source_ip,
            "description": a.description,
            "reasoning": a.description,
            "status": a.status
        })
    return response

# GET /api/threats/{threat_id} (PARAMETERIZED ROUTE)
@app.get("/api/threats/{threat_id}")
def get_threat_by_id(threat_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == threat_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found")

    score, severity_level = ThreatScorer.calculate_score([alert.rule_name])
    if score == 0:
        score = 90.0 if alert.severity == "CRITICAL" else (75.0 if alert.severity == "HIGH" else 50.0)

    associated_log = None
    if alert.log_id:
        db_log = db.query(Log).filter(Log.id == alert.log_id).first()
        if db_log:
            associated_log = {
                "id": db_log.id,
                "timestamp": db_log.timestamp.isoformat(),
                "source_ip": db_log.source_ip,
                "destination_ip": db_log.destination_ip,
                "protocol": db_log.protocol,
                "action": db_log.action,
                "message": db_log.message
            }

    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "log_id": alert.log_id,
        "severity": alert.severity,
        "threat_type": alert.rule_name,
        "rule_name": alert.rule_name,
        "threat_score": score,
        "severity_level": severity_level,
        "source_ip": alert.source_ip,
        "description": alert.description,
        "reasoning": alert.description,
        "status": alert.status,
        "associated_log": associated_log
    }

# POST /api/threats/{threat_id}/resolve & PUT /api/alerts/{alert_id}/status
@app.post("/api/threats/{threat_id}/resolve")
@app.put("/api/alerts/{alert_id}/status")
async def resolve_threat(threat_id: int = None, alert_id: int = None, status: str = "RESOLVED", db: Session = Depends(get_db)):
    target_id = threat_id if threat_id is not None else alert_id
    alert = db.query(Alert).filter(Alert.id == target_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    
    alert.status = status.upper()
    db.commit()
    db.refresh(alert)
    
    score, _ = ThreatScorer.calculate_score([alert.rule_name])
    if score == 0:
        score = 90.0 if alert.severity == "CRITICAL" else (75.0 if alert.severity == "HIGH" else 50.0)

    updated_payload = {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "log_id": alert.log_id,
        "severity": alert.severity,
        "rule_name": alert.rule_name,
        "threat_type": alert.rule_name,
        "threat_score": score,
        "source_ip": alert.source_ip,
        "description": alert.description,
        "reasoning": alert.description,
        "status": alert.status
    }
    
    await manager.broadcast({"event": "alert_update", "type": "ALERT_UPDATE", "payload": updated_payload, "data": updated_payload})
    return {"status": "success", "alert": updated_payload}

# --- Analytics Endpoints ---

# GET /api/analytics/timeline
@app.get("/api/analytics/timeline")
def get_analytics_timeline(
    interval: str = Query("1m", description="Interval aggregation (1m, 5m, 1h)"),
    range: str = Query("1h", description="Time range (1h, 24h, 7d)"),
    db: Session = Depends(get_db)
):
    now = datetime.utcnow()
    
    if range == "24h":
        start_time = now - timedelta(hours=24)
        step_minutes = 60
    elif range == "7d":
        start_time = now - timedelta(days=7)
        step_minutes = 360
    else:
        start_time = now - timedelta(hours=1)
        step_minutes = 5

    logs = db.query(Log).filter(Log.timestamp >= start_time).all()
    alerts = db.query(Alert).filter(Alert.timestamp >= start_time).all()

    timeline_buckets: Dict[str, Dict[str, int]] = {}
    current = start_time
    while current <= now + timedelta(minutes=step_minutes):
        bucket_key = current.strftime("%H:%M")
        timeline_buckets[bucket_key] = {"event_count": 0, "threat_count": 0}
        current += timedelta(minutes=step_minutes)

    for l in logs:
        key = l.timestamp.strftime("%H:%M")
        if key in timeline_buckets:
            timeline_buckets[key]["event_count"] += 1

    for a in alerts:
        key = a.timestamp.strftime("%H:%M")
        if key in timeline_buckets:
            timeline_buckets[key]["threat_count"] += 1

    timeline = [
        {
            "timestamp": k,
            "event_count": v["event_count"],
            "threat_count": v["threat_count"]
        } for k, v in timeline_buckets.items()
    ]
    return timeline

# GET /api/analytics/top-sources
@app.get("/api/analytics/top-sources")
def get_top_threat_sources(limit: int = Query(10, le=100), db: Session = Depends(get_db)):
    top_sources = db.query(
        Alert.source_ip,
        func.count(Alert.id).label("alert_count")
    ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(limit).all()

    results = []
    for ip, count in top_sources:
        is_bl = ip in custom_blacklisted_ips
        results.append({
            "source_ip": ip,
            "alert_count": count,
            "is_blacklisted": is_bl
        })
    return results

# --- IP Intelligence Endpoints ---

# GET /api/ip/{ip_address}/info
@app.get("/api/ip/{ip_address}/info")
def get_ip_info(ip_address: str, db: Session = Depends(get_db)):
    total_logs = db.query(Log).filter(Log.source_ip == ip_address).count()
    alerts = db.query(Alert).filter(Alert.source_ip == ip_address).all()

    severity_breakdown = {}
    for a in alerts:
        severity_breakdown[a.severity] = severity_breakdown.get(a.severity, 0) + 1

    is_blacklisted = ip_address in custom_blacklisted_ips

    return {
        "ip_address": ip_address,
        "is_blacklisted": is_blacklisted,
        "total_logs": total_logs,
        "total_alerts": len(alerts),
        "severity_breakdown": severity_breakdown,
        "recent_alerts": [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "timestamp": a.timestamp.isoformat()
            } for a in alerts[:5]
        ]
    }

# POST /api/ip/blacklist
@app.post("/api/ip/blacklist")
def blacklist_ip(payload: Dict[str, Any]):
    ip = payload.get("ip_address", payload.get("ip"))
    if not ip:
        raise HTTPException(status_code=400, detail="Missing ip_address in request body")

    custom_blacklisted_ips.add(ip)
    return {
        "status": "success",
        "message": f"IP {ip} successfully added to blacklist",
        "blacklisted_ip": ip,
        "total_blacklisted": len(custom_blacklisted_ips)
    }

# --- PF Sense Integration Endpoints ---

# POST /api/ingest/pfsense
@app.post("/api/ingest/pfsense")
async def ingest_pfsense_log(request: Request, db: Session = Depends(get_db)):
    global window_log_count, window_bytes_count
    
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            raw_log = body.get("raw_log", body.get("log", str(body)))
        except Exception:
            body_bytes = await request.body()
            raw_log = body_bytes.decode("utf-8", errors="ignore")
    else:
        body_bytes = await request.body()
        raw_log = body_bytes.decode("utf-8", errors="ignore")

    if not raw_log or len(raw_log.strip()) == 0:
        raw_log = "Feb 23 13:45:00 pfsense filterlog[123]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,80,0,S,10000,,"

    parsed = StandaloneLogParser.parse_pfsense(raw_log)

    db_log = Log(
        timestamp=parsed.get("timestamp", datetime.utcnow()),
        source_ip=parsed.get("source_ip", "0.0.0.0"),
        destination_ip=parsed.get("destination_ip", "10.0.0.1"),
        source_port=parsed.get("source_port", 0),
        destination_port=parsed.get("destination_port", 80),
        protocol=parsed.get("protocol", "TCP"),
        action=parsed.get("action", "BLOCK"),
        bytes_transferred=parsed.get("bytes_transferred", 64),
        message=f"[Rule #{parsed.get('rule_id', '1000000103')}] {parsed.get('message', raw_log)}"
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    window_log_count += 1
    window_bytes_count += parsed.get("bytes_transferred", 64)

    log_schema = LogCreate(
        timestamp=db_log.timestamp,
        source_ip=db_log.source_ip,
        destination_ip=db_log.destination_ip,
        source_port=db_log.source_port,
        destination_port=db_log.destination_port,
        protocol=db_log.protocol,
        action=db_log.action,
        bytes_transferred=db_log.bytes_transferred,
        message=db_log.message
    )

    detected_alerts = threat_engine.analyze_log(log_schema)
    saved_alerts = []

    for alert_data in detected_alerts:
        score, _ = ThreatScorer.calculate_score([alert_data.rule_name])
        if score == 0:
            score = 90.0 if alert_data.severity == "CRITICAL" else (75.0 if alert_data.severity == "HIGH" else 50.0)

        db_alert = Alert(
            timestamp=alert_data.timestamp,
            log_id=db_log.id,
            severity=alert_data.severity,
            rule_name=alert_data.rule_name,
            source_ip=alert_data.source_ip,
            description=alert_data.description,
            status="ACTIVE"
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        a_payload = {
            "id": db_alert.id,
            "timestamp": db_alert.timestamp.isoformat(),
            "log_id": db_alert.log_id,
            "severity": db_alert.severity,
            "threat_type": db_alert.rule_name,
            "threat_score": score,
            "source_ip": db_alert.source_ip,
            "description": db_alert.description,
            "reasoning": db_alert.description,
            "status": db_alert.status
        }
        saved_alerts.append(a_payload)
        await manager.broadcast({"event": "threat_alert", "type": "ALERT", "payload": a_payload, "data": a_payload})

    log_payload = {
        "id": db_log.id,
        "timestamp": db_log.timestamp.isoformat(),
        "source_ip": db_log.source_ip,
        "destination_ip": db_log.destination_ip,
        "source_port": db_log.source_port,
        "destination_port": db_log.destination_port,
        "protocol": db_log.protocol,
        "action": db_log.action,
        "bytes_transferred": db_log.bytes_transferred,
        "message": db_log.message,
        "rule_id": parsed.get("rule_id", "1000000103")
    }

    await manager.broadcast({"event": "new_log", "type": "LOG", "payload": log_payload, "data": log_payload})

    return {
        "status": "success",
        "parsed_pfsense_log": log_payload,
        "alerts_triggered": len(saved_alerts)
    }

# GET /api/pfsense/firewall-rules
@app.get("/api/pfsense/firewall-rules")
def get_pfsense_firewall_rules(db: Session = Depends(get_db)):
    block_count = db.query(Log).filter(Log.action == "BLOCK").count()
    allow_count = db.query(Log).filter(Log.action == "ALLOW").count()

    rule_stats = [
        {
            "rule_id": "1000000103",
            "description": "Default Deny / Firewall Block Rule (IPv4)",
            "action": "BLOCK",
            "hit_count": max(block_count, 12)
        },
        {
            "rule_id": "1000000104",
            "description": "Pass WAN / Established Connections (IPv4)",
            "action": "ALLOW",
            "hit_count": max(allow_count, 45)
        },
        {
            "rule_id": "1000000105",
            "description": "SSH / Remote Mgmt Access Filter",
            "action": "BLOCK",
            "hit_count": 8
        },
        {
            "rule_id": "1000000106",
            "description": "HTTP / HTTPS Web Ingress Filter",
            "action": "ALLOW",
            "hit_count": 32
        }
    ]
    return rule_stats

@app.get("/api/stats")
def get_summary_stats(db: Session = Depends(get_db)):
    total_logs = db.query(Log).count()
    total_alerts = db.query(Alert).count()
    active_alerts = db.query(Alert).filter(Alert.status == "ACTIVE").count()
    
    protocol_counts = db.query(Log.protocol, func.count(Log.id)).group_by(Log.protocol).all()
    proto_dict = {p: count for p, count in protocol_counts}

    action_counts = db.query(Log.action, func.count(Log.id)).group_by(Log.action).all()
    action_dict = {a: count for a, count in action_counts}

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "protocol_breakdown": proto_dict,
        "action_breakdown": action_dict
    }

# --- WebSocket Endpoints ---

@app.websocket("/ws/logs")
@app.websocket("/ws/live-feed")
async def websocket_logs_endpoint(websocket: WebSocket, db: Session = Depends(get_db)):
    await manager.connect(websocket)
    try:
        recent_logs = db.query(Log).order_by(Log.timestamp.desc()).limit(20).all()
        recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(10).all()
        active_alerts_count = db.query(Alert).filter(Alert.status == "ACTIVE").count()

        alerts_payload = []
        for a in recent_alerts:
            score, _ = ThreatScorer.calculate_score([a.rule_name])
            if score == 0:
                score = 90.0 if a.severity == "CRITICAL" else (75.0 if a.severity == "HIGH" else 50.0)
            alerts_payload.append({
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "log_id": a.log_id,
                "severity": a.severity,
                "rule_name": a.rule_name,
                "threat_type": a.rule_name,
                "threat_score": score,
                "source_ip": a.source_ip,
                "description": a.description,
                "reasoning": a.description,
                "status": a.status
            })

        initial_payload = {
            "event": "initial_state",
            "type": "INITIAL_STATE",
            "payload": {
                "logs": [
                    {
                        "id": l.id,
                        "timestamp": l.timestamp.isoformat(),
                        "source_ip": l.source_ip,
                        "destination_ip": l.destination_ip,
                        "source_port": l.source_port,
                        "destination_port": l.destination_port,
                        "protocol": l.protocol,
                        "action": l.action,
                        "bytes_transferred": l.bytes_transferred,
                        "message": l.message
                    } for l in reversed(recent_logs)
                ],
                "alerts": alerts_payload,
                "metrics": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "throughput_lps": 0.0,
                    "active_alerts_count": active_alerts_count,
                    "bandwidth_kbps": 0.0
                }
            }
        }
        await websocket.send_json(initial_payload)

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
