import asyncio
import time
import os
from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import select, insert, update, func, and_
from sqlalchemy.engine import Connection

from .database import get_db, init_db, engine
from .models import logs_table, threat_alerts_table, metrics_snapshots_table, blacklisted_ips_table
from .schemas import LogCreate
from .parser import LogParser
from .log_parser import LogParser as StandaloneLogParser
from .threat_engine import threat_engine
from .websocket_manager import manager
from .threat_scorer import ThreatScorer
from .threat_detector import DEFAULT_BLACKLISTED_IPS
from .geoip_helper import get_geoip_data

app = FastAPI(
    title="Real-Time Network Monitoring & Threat Detection API (SQLAlchemy Core)",
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

# Mount Frontend Static Assets & Serve React Single-Page Application
frontend_dist_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")

if os.path.exists(os.path.join(frontend_dist_dir, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist_dir, "assets")), name="assets")

# Global memory counters for throughput calculation
window_log_count = 0
window_bytes_count = 0
last_metrics_calc_time = time.time()
custom_blacklisted_ips = set(DEFAULT_BLACKLISTED_IPS)

@app.on_event("startup")
def on_startup():
    init_db()
    try:
        with engine.connect() as conn:
            # Seed default blacklisted IPs if table empty
            count_stmt = select(func.count()).select_from(blacklisted_ips_table)
            count = conn.execute(count_stmt).scalar() or 0
            if count == 0:
                defaults = [
                    {"ip_address": "45.33.32.156", "danger_level": "CRITICAL", "reason": "Known Threat Intelligence Feed - Malicious Scanner"},
                    {"ip_address": "185.220.101.5", "danger_level": "CRITICAL", "reason": "Tor Exit Node - High Risk Intrusion Attempt"},
                    {"ip_address": "193.142.146.210", "danger_level": "HIGH", "reason": "SQL Injection & Vulnerability Probe Source"},
                    {"ip_address": "103.251.167.20", "danger_level": "HIGH", "reason": "Brute Force Authentication Attacker"}
                ]
                for item in defaults:
                    conn.execute(insert(blacklisted_ips_table).values(**item))
                conn.commit()

            rows = conn.execute(select(blacklisted_ips_table.c.ip_address)).all()
            for ip_row in rows:
                custom_blacklisted_ips.add(ip_row[0])
    except Exception:
        pass

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

        try:
            with engine.connect() as conn:
                # Count active alerts using Core select
                active_count_stmt = select(func.count()).select_from(threat_alerts_table).where(threat_alerts_table.c.status == "ACTIVE")
                active_alerts = conn.execute(active_count_stmt).scalar() or 0

                ts_now = datetime.utcnow()
                insert_snapshot_stmt = insert(metrics_snapshots_table).values(
                    timestamp=ts_now,
                    throughput_lps=lps,
                    active_alerts_count=active_alerts,
                    bandwidth_kbps=kbps
                )
                conn.execute(insert_snapshot_stmt)
                conn.commit()

                metrics_payload = {
                    "timestamp": ts_now.isoformat(),
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
            pass

# --- REST Endpoints (SQLAlchemy Core) ---

@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dist_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Real-Time Network Monitoring & Threat Detection System (SQLAlchemy Core)"}

# Real-time Monitoring Endpoint: POST /api/ingest/log
@app.post("/api/ingest/log")
@app.post("/api/logs")
async def ingest_log(raw_log: Union[Dict[str, Any], str], conn: Connection = Depends(get_db)):
    global window_log_count, window_bytes_count
    
    # 1. Parse log
    log_data = LogParser.parse_and_normalize(raw_log)
    
    # Check custom blacklist
    if log_data.source_ip in custom_blacklisted_ips:
        log_data.action = "BLOCK"

    geoip = get_geoip_data(log_data.source_ip)

    # 2. Insert log into database using SQLAlchemy Core insert()
    insert_log_stmt = insert(logs_table).values(
        timestamp=log_data.timestamp,
        source_ip=log_data.source_ip,
        destination_ip=log_data.destination_ip,
        source_port=log_data.source_port,
        destination_port=log_data.destination_port,
        protocol=log_data.protocol,
        action=log_data.action,
        bytes_transferred=log_data.bytes_transferred,
        event_type=log_data.action.lower(),
        severity=log_data.severity if hasattr(log_data, 'severity') else "LOW",
        country_code=geoip["country_code"],
        country_name=geoip["country_name"],
        message=log_data.message
    ).returning(logs_table.c.id)
    
    inserted_log_id = conn.execute(insert_log_stmt).scalar()
    conn.commit()

    window_log_count += 1
    window_bytes_count += log_data.bytes_transferred

    # 3. Analyze for threats & calculate threat score/reasoning
    detected_alerts = threat_engine.analyze_log(log_data)
    saved_alerts_payloads = []
    
    for alert_data in detected_alerts:
        score, _ = ThreatScorer.calculate_score([alert_data.rule_name])
        if score == 0:
            score = 90.0 if alert_data.severity == "CRITICAL" else (75.0 if alert_data.severity == "HIGH" else 50.0)

        insert_alert_stmt = insert(threat_alerts_table).values(
            timestamp=alert_data.timestamp,
            log_id=inserted_log_id,
            rule_name=alert_data.rule_name,
            threat_type=alert_data.rule_name,
            threat_score=score,
            severity=alert_data.severity,
            source_ip=alert_data.source_ip,
            country_code=geoip["country_code"],
            country_name=geoip["country_name"],
            description=alert_data.description,
            status="ACTIVE"
        ).returning(threat_alerts_table.c.id)
        
        inserted_alert_id = conn.execute(insert_alert_stmt).scalar()
        conn.commit()
        
        alert_payload = {
            "id": inserted_alert_id,
            "timestamp": alert_data.timestamp.isoformat(),
            "log_id": inserted_log_id,
            "severity": alert_data.severity,
            "threat_type": alert_data.rule_name,
            "rule_name": alert_data.rule_name,
            "threat_score": score,
            "source_ip": alert_data.source_ip,
            "description": alert_data.description,
            "reasoning": alert_data.description,
            "status": "ACTIVE"
        }
        saved_alerts_payloads.append(alert_payload)

    # 4. Immediate WebSocket Broadcast
    log_payload = {
        "id": inserted_log_id,
        "timestamp": log_data.timestamp.isoformat(),
        "source_ip": log_data.source_ip,
        "destination_ip": log_data.destination_ip,
        "source_port": log_data.source_port,
        "destination_port": log_data.destination_port,
        "protocol": log_data.protocol,
        "action": log_data.action,
        "bytes_transferred": log_data.bytes_transferred,
        "message": log_data.message
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
    conn: Connection = Depends(get_db)
):
    stmt = select(logs_table)
    
    conditions = []
    if source_ip:
        conditions.append(logs_table.c.source_ip.contains(source_ip))
    if protocol:
        conditions.append(logs_table.c.protocol == protocol.upper())
    if action:
        conditions.append(logs_table.c.action == action.upper())
        
    if conditions:
        stmt = stmt.where(and_(*conditions))
        
    stmt = stmt.order_by(logs_table.c.timestamp.desc()).limit(limit)
    rows = conn.execute(stmt).mappings().all()
    
    result = []
    for r in rows:
        dict_row = dict(r)
        if isinstance(dict_row.get("timestamp"), datetime):
            dict_row["timestamp"] = dict_row["timestamp"].isoformat()
        if isinstance(dict_row.get("created_at"), datetime):
            dict_row["created_at"] = dict_row["created_at"].isoformat()
        result.append(dict_row)
    return result

# --- Threat Detection Endpoints (SQLAlchemy Core) ---

# GET /api/threats/stats
@app.get("/api/threats/stats")
def get_threat_stats(conn: Connection = Depends(get_db)):
    total_stmt = select(func.count()).select_from(threat_alerts_table)
    total_threats = conn.execute(total_stmt).scalar() or 0

    active_stmt = select(func.count()).select_from(threat_alerts_table).where(threat_alerts_table.c.status == "ACTIVE")
    active_threats = conn.execute(active_stmt).scalar() or 0

    sev_stmt = select(threat_alerts_table.c.severity, func.count(threat_alerts_table.c.id)).group_by(threat_alerts_table.c.severity)
    sev_rows = conn.execute(sev_stmt).all()
    by_severity = {s: count for s, count in sev_rows}

    type_stmt = select(threat_alerts_table.c.rule_name, func.count(threat_alerts_table.c.id)).group_by(threat_alerts_table.c.rule_name)
    type_rows = conn.execute(type_stmt).all()
    by_type = {t: count for t, count in type_rows if t}

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
    conn: Connection = Depends(get_db)
):
    stmt = select(threat_alerts_table)
    conditions = []
    
    if severity:
        conditions.append(threat_alerts_table.c.severity == severity.upper())
    if from_date:
        try:
            dt_from = datetime.fromisoformat(from_date)
            conditions.append(threat_alerts_table.c.timestamp >= dt_from)
        except ValueError:
            pass
    if to_date:
        try:
            dt_to = datetime.fromisoformat(to_date)
            conditions.append(threat_alerts_table.c.timestamp <= dt_to)
        except ValueError:
            pass
            
    if conditions:
        stmt = stmt.where(and_(*conditions))
        
    stmt = stmt.order_by(threat_alerts_table.c.timestamp.desc()).limit(limit)
    rows = conn.execute(stmt).mappings().all()
    
    response = []
    for a in rows:
        rule_name = a.get("rule_name") or a.get("threat_type") or "SECURITY_ALERT"
        score = a.get("threat_score", 0.0)
        if score == 0:
            score, _ = ThreatScorer.calculate_score([rule_name])
            if score == 0:
                score = 90.0 if a.get("severity") == "CRITICAL" else (75.0 if a.get("severity") == "HIGH" else 50.0)

        ts = a.get("timestamp")
        ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)

        response.append({
            "id": a["id"],
            "log_id": a.get("log_id"),
            "timestamp": ts_str,
            "severity": a["severity"],
            "threat_type": rule_name,
            "rule_name": rule_name,
            "threat_score": score,
            "source_ip": a.get("source_ip"),
            "description": a["description"],
            "reasoning": a["description"],
            "status": a.get("status", "ACTIVE")
        })
    return response

# GET /api/threats/{threat_id}
@app.get("/api/threats/{threat_id}")
def get_threat_by_id(threat_id: int, conn: Connection = Depends(get_db)):
    stmt = select(threat_alerts_table).where(threat_alerts_table.c.id == threat_id)
    alert = conn.execute(stmt).mappings().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found")

    rule_name = alert.get("rule_name") or alert.get("threat_type") or "SECURITY_ALERT"
    score = alert.get("threat_score", 0.0)
    score_calc, severity_level = ThreatScorer.calculate_score([rule_name])
    if score == 0:
        score = score_calc if score_calc > 0 else (90.0 if alert.get("severity") == "CRITICAL" else 50.0)

    associated_log = None
    if alert.get("log_id"):
        log_stmt = select(logs_table).where(logs_table.c.id == alert["log_id"])
        db_log = conn.execute(log_stmt).mappings().first()
        if db_log:
            ts_log = db_log.get("timestamp")
            associated_log = {
                "id": db_log["id"],
                "timestamp": ts_log.isoformat() if isinstance(ts_log, datetime) else str(ts_log),
                "source_ip": db_log["source_ip"],
                "destination_ip": db_log["destination_ip"],
                "protocol": db_log.get("protocol"),
                "action": db_log.get("action"),
                "message": db_log.get("message")
            }

    ts = alert.get("timestamp")
    return {
        "id": alert["id"],
        "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        "log_id": alert.get("log_id"),
        "severity": alert["severity"],
        "threat_type": rule_name,
        "rule_name": rule_name,
        "threat_score": score,
        "severity_level": severity_level,
        "source_ip": alert.get("source_ip"),
        "description": alert["description"],
        "reasoning": alert["description"],
        "status": alert.get("status", "ACTIVE"),
        "associated_log": associated_log
    }

# POST /api/threats/{threat_id}/resolve & PUT /api/alerts/{alert_id}/status
@app.post("/api/threats/{threat_id}/resolve")
@app.put("/api/alerts/{alert_id}/status")
async def resolve_threat(threat_id: int = None, alert_id: int = None, status: str = "RESOLVED", conn: Connection = Depends(get_db)):
    target_id = threat_id if threat_id is not None else alert_id
    
    update_stmt = update(threat_alerts_table).where(threat_alerts_table.c.id == target_id).values(
        status=status.upper(),
        is_resolved=(status.upper() == "RESOLVED")
    ).returning(threat_alerts_table)
    
    row = conn.execute(update_stmt).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    conn.commit()
    
    rule_name = row.get("rule_name") or row.get("threat_type") or "SECURITY_ALERT"
    score = row.get("threat_score", 0.0)
    if score == 0:
        score, _ = ThreatScorer.calculate_score([rule_name])
        if score == 0:
            score = 90.0 if row.get("severity") == "CRITICAL" else 50.0

    ts = row.get("timestamp")
    updated_payload = {
        "id": row["id"],
        "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        "log_id": row.get("log_id"),
        "severity": row["severity"],
        "rule_name": rule_name,
        "threat_type": rule_name,
        "threat_score": score,
        "source_ip": row.get("source_ip"),
        "description": row["description"],
        "reasoning": row["description"],
        "status": row.get("status")
    }
    
    await manager.broadcast({"event": "alert_update", "type": "ALERT_UPDATE", "payload": updated_payload, "data": updated_payload})
    return {"status": "success", "alert": updated_payload}

# --- Analytics Endpoints (SQLAlchemy Core) ---

# GET /api/analytics/timeline
@app.get("/api/analytics/timeline")
def get_analytics_timeline(
    interval: str = Query("1m", description="Interval aggregation (1m, 5m, 1h)"),
    range: str = Query("1h", description="Time range (1h, 24h, 7d)"),
    conn: Connection = Depends(get_db)
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

    logs_stmt = select(logs_table.c.timestamp).where(logs_table.c.timestamp >= start_time)
    log_rows = conn.execute(logs_stmt).all()

    alerts_stmt = select(threat_alerts_table.c.timestamp).where(threat_alerts_table.c.timestamp >= start_time)
    alert_rows = conn.execute(alerts_stmt).all()

    timeline_buckets: Dict[str, Dict[str, int]] = {}
    current = start_time
    while current <= now + timedelta(minutes=step_minutes):
        bucket_key = current.strftime("%H:%M")
        timeline_buckets[bucket_key] = {"event_count": 0, "threat_count": 0}
        current += timedelta(minutes=step_minutes)

    for l_ts, in log_rows:
        if isinstance(l_ts, datetime):
            key = l_ts.strftime("%H:%M")
            if key in timeline_buckets:
                timeline_buckets[key]["event_count"] += 1

    for a_ts, in alert_rows:
        if isinstance(a_ts, datetime):
            key = a_ts.strftime("%H:%M")
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
def get_top_threat_sources(limit: int = Query(10, le=100), conn: Connection = Depends(get_db)):
    stmt = select(
        threat_alerts_table.c.source_ip,
        func.count(threat_alerts_table.c.id).label("alert_count")
    ).group_by(threat_alerts_table.c.source_ip).order_by(func.count(threat_alerts_table.c.id).desc()).limit(limit)

    top_sources = conn.execute(stmt).all()

    results = []
    for ip, count in top_sources:
        if ip:
            results.append({
                "source_ip": ip,
                "alert_count": count,
                "is_blacklisted": ip in custom_blacklisted_ips
            })
    return results

# --- IP Intelligence Endpoints (SQLAlchemy Core) ---

# GET /api/ip/blacklist
@app.get("/api/ip/blacklist")
def get_blacklisted_ips(conn: Connection = Depends(get_db)):
    stmt = select(blacklisted_ips_table).order_by(blacklisted_ips_table.c.created_at.desc())
    rows = conn.execute(stmt).mappings().all()

    result = []
    for r in rows:
        ip = r["ip_address"]
        threat_cnt_stmt = select(func.count()).select_from(threat_alerts_table).where(threat_alerts_table.c.source_ip == ip)
        threat_count = conn.execute(threat_cnt_stmt).scalar() or 0

        created_at = r.get("created_at")
        result.append({
            "id": r["id"],
            "ip_address": ip,
            "danger_level": r.get("danger_level", "HIGH"),
            "reason": r.get("reason", "Security Violation"),
            "created_at": created_at.isoformat() if isinstance(created_at, datetime) else str(created_at),
            "threat_count": threat_count
        })
    return result

# POST /api/ip/blacklist (Block IP)
@app.post("/api/ip/blacklist")
def blacklist_ip(payload: Dict[str, Any], conn: Connection = Depends(get_db)):
    ip = payload.get("ip_address", payload.get("ip"))
    danger_level = str(payload.get("danger_level", "HIGH")).upper()
    reason = payload.get("reason", "Manual Administrative Block")

    if not ip:
        raise HTTPException(status_code=400, detail="Missing ip_address in request body")

    if danger_level not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        danger_level = "HIGH"

    custom_blacklisted_ips.add(ip)

    check_stmt = select(blacklisted_ips_table).where(blacklisted_ips_table.c.ip_address == ip)
    existing = conn.execute(check_stmt).mappings().first()

    if existing:
        update_stmt = update(blacklisted_ips_table).where(blacklisted_ips_table.c.ip_address == ip).values(
            danger_level=danger_level,
            reason=reason
        )
        conn.execute(update_stmt)
    else:
        insert_stmt = insert(blacklisted_ips_table).values(
            ip_address=ip,
            danger_level=danger_level,
            reason=reason
        )
        conn.execute(insert_stmt)

    conn.commit()

    return {
        "status": "success",
        "message": f"IP {ip} successfully added to blacklist with danger level {danger_level}",
        "blacklisted_ip": ip,
        "danger_level": danger_level,
        "reason": reason
    }

# POST /api/ip/unblacklist & DELETE /api/ip/blacklist/{ip_address} (Unblock IP)
@app.post("/api/ip/unblacklist")
@app.delete("/api/ip/blacklist/{ip_address:path}")
def unblacklist_ip(ip_address: Optional[str] = None, payload: Optional[Dict[str, Any]] = None, conn: Connection = Depends(get_db)):
    target_ip = ip_address
    if not target_ip and payload:
        target_ip = payload.get("ip_address", payload.get("ip"))

    if not target_ip:
        raise HTTPException(status_code=400, detail="Missing ip_address")

    if target_ip in custom_blacklisted_ips:
        custom_blacklisted_ips.remove(target_ip)

    del_stmt = blacklisted_ips_table.delete().where(blacklisted_ips_table.c.ip_address == target_ip)
    conn.execute(del_stmt)
    conn.commit()

    return {
        "status": "success",
        "message": f"IP {target_ip} successfully unblocked and removed from blacklist",
        "unblocked_ip": target_ip
    }

# GET /api/ip/{ip_address}/info
@app.get("/api/ip/{ip_address}/info")
def get_ip_info(ip_address: str, conn: Connection = Depends(get_db)):
    logs_count_stmt = select(func.count()).select_from(logs_table).where(logs_table.c.source_ip == ip_address)
    total_logs = conn.execute(logs_count_stmt).scalar() or 0

    alerts_stmt = select(threat_alerts_table).where(threat_alerts_table.c.source_ip == ip_address)
    alerts = conn.execute(alerts_stmt).mappings().all()

    severity_breakdown = {}
    for a in alerts:
        sev = a["severity"]
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    bl_stmt = select(blacklisted_ips_table).where(blacklisted_ips_table.c.ip_address == ip_address)
    bl_record = conn.execute(bl_stmt).mappings().first()
    is_blacklisted = ip_address in custom_blacklisted_ips or bool(bl_record)

    recent_alerts = []
    for a in alerts[:5]:
        ts = a.get("timestamp")
        recent_alerts.append({
            "id": a["id"],
            "rule_name": a.get("rule_name") or a.get("threat_type"),
            "severity": a["severity"],
            "description": a["description"],
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts)
        })

    return {
        "ip_address": ip_address,
        "is_blacklisted": is_blacklisted,
        "danger_level": bl_record["danger_level"] if bl_record else ("HIGH" if is_blacklisted else "LOW"),
        "reason": bl_record["reason"] if bl_record else None,
        "total_logs": total_logs,
        "total_alerts": len(alerts),
        "severity_breakdown": severity_breakdown,
        "recent_alerts": recent_alerts
    }

# --- PF Sense Integration Endpoints (SQLAlchemy Core) ---

# POST /api/ingest/pfsense
@app.post("/api/ingest/pfsense")
async def ingest_pfsense_log(request: Request, conn: Connection = Depends(get_db)):
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
    ts = parsed.get("timestamp", datetime.utcnow())

    insert_log_stmt = insert(logs_table).values(
        timestamp=ts,
        source_ip=parsed.get("source_ip", "0.0.0.0"),
        destination_ip=parsed.get("destination_ip", "10.0.0.1"),
        source_port=parsed.get("source_port", 0),
        destination_port=parsed.get("destination_port", 80),
        protocol=parsed.get("protocol", "TCP"),
        action=parsed.get("action", "BLOCK"),
        event_type=parsed.get("event_type", "firewall_block"),
        severity=parsed.get("severity", "HIGH"),
        bytes_transferred=parsed.get("bytes_transferred", 64),
        message=f"[Rule #{parsed.get('rule_id', '1000000103')}] {parsed.get('message', raw_log)}"
    ).returning(logs_table.c.id)

    inserted_log_id = conn.execute(insert_log_stmt).scalar()
    conn.commit()

    window_log_count += 1
    window_bytes_count += parsed.get("bytes_transferred", 64)

    log_schema = LogCreate(
        timestamp=ts,
        source_ip=parsed.get("source_ip", "0.0.0.0"),
        destination_ip=parsed.get("destination_ip", "10.0.0.1"),
        source_port=parsed.get("source_port", 0),
        destination_port=parsed.get("destination_port", 80),
        protocol=parsed.get("protocol", "TCP"),
        action=parsed.get("action", "BLOCK"),
        bytes_transferred=parsed.get("bytes_transferred", 64),
        message=parsed.get("message", raw_log)
    )

    detected_alerts = threat_engine.analyze_log(log_schema)
    saved_alerts = []

    for alert_data in detected_alerts:
        score, _ = ThreatScorer.calculate_score([alert_data.rule_name])
        if score == 0:
            score = 90.0 if alert_data.severity == "CRITICAL" else (75.0 if alert_data.severity == "HIGH" else 50.0)

        insert_alert_stmt = insert(threat_alerts_table).values(
            timestamp=alert_data.timestamp,
            log_id=inserted_log_id,
            rule_name=alert_data.rule_name,
            threat_type=alert_data.rule_name,
            threat_score=score,
            severity=alert_data.severity,
            source_ip=alert_data.source_ip,
            description=alert_data.description,
            status="ACTIVE"
        ).returning(threat_alerts_table.c.id)

        inserted_alert_id = conn.execute(insert_alert_stmt).scalar()
        conn.commit()

        a_payload = {
            "id": inserted_alert_id,
            "timestamp": alert_data.timestamp.isoformat(),
            "log_id": inserted_log_id,
            "severity": alert_data.severity,
            "threat_type": alert_data.rule_name,
            "threat_score": score,
            "source_ip": alert_data.source_ip,
            "description": alert_data.description,
            "reasoning": alert_data.description,
            "status": "ACTIVE"
        }
        saved_alerts.append(a_payload)
        await manager.broadcast({"event": "threat_alert", "type": "ALERT", "payload": a_payload, "data": a_payload})

    log_payload = {
        "id": inserted_log_id,
        "timestamp": ts.isoformat(),
        "source_ip": parsed.get("source_ip", "0.0.0.0"),
        "destination_ip": parsed.get("destination_ip", "10.0.0.1"),
        "source_port": parsed.get("source_port", 0),
        "destination_port": parsed.get("destination_port", 80),
        "protocol": parsed.get("protocol", "TCP"),
        "action": parsed.get("action", "BLOCK"),
        "bytes_transferred": parsed.get("bytes_transferred", 64),
        "message": f"[Rule #{parsed.get('rule_id', '1000000103')}] {parsed.get('message', raw_log)}",
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
def get_pfsense_firewall_rules(conn: Connection = Depends(get_db)):
    block_stmt = select(func.count()).select_from(logs_table).where(logs_table.c.action == "BLOCK")
    block_count = conn.execute(block_stmt).scalar() or 0

    allow_stmt = select(func.count()).select_from(logs_table).where(logs_table.c.action == "ALLOW")
    allow_count = conn.execute(allow_stmt).scalar() or 0

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
def get_summary_stats(conn: Connection = Depends(get_db)):
    total_logs_stmt = select(func.count()).select_from(logs_table)
    total_logs = conn.execute(total_logs_stmt).scalar() or 0

    total_alerts_stmt = select(func.count()).select_from(threat_alerts_table)
    total_alerts = conn.execute(total_alerts_stmt).scalar() or 0

    active_alerts_stmt = select(func.count()).select_from(threat_alerts_table).where(threat_alerts_table.c.status == "ACTIVE")
    active_alerts = conn.execute(active_alerts_stmt).scalar() or 0
    
    proto_stmt = select(logs_table.c.protocol, func.count(logs_table.c.id)).group_by(logs_table.c.protocol)
    proto_dict = {p: count for p, count in conn.execute(proto_stmt).all() if p}

    action_stmt = select(logs_table.c.action, func.count(logs_table.c.id)).group_by(logs_table.c.action)
    action_dict = {a: count for a, count in conn.execute(action_stmt).all() if a}

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "protocol_breakdown": proto_dict,
        "action_breakdown": action_dict
    }

# POST /api/simulate/attack
from .enterprise_simulator import enterprise_simulator

@app.post("/api/simulate/attack")
def simulate_enterprise_attack(payload: Dict[str, Any]):
    scenario = payload.get("scenario", "L7_DDOS")
    count = int(payload.get("count", 5))
    
    injected = enterprise_simulator.inject_log_batch(count=count)
    return {
        "status": "success",
        "scenario": scenario,
        "logs_injected": injected,
        "message": f"Successfully injected {injected} high-volume enterprise attack logs into real-time threat engine"
    }

# --- WebSocket Endpoints (SQLAlchemy Core) ---

@app.websocket("/ws/logs")
@app.websocket("/ws/live-feed")
async def websocket_logs_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        with engine.connect() as conn:
            logs_stmt = select(logs_table).order_by(logs_table.c.timestamp.desc()).limit(20)
            recent_logs = conn.execute(logs_stmt).mappings().all()

            alerts_stmt = select(threat_alerts_table).order_by(threat_alerts_table.c.timestamp.desc()).limit(10)
            recent_alerts = conn.execute(alerts_stmt).mappings().all()

            active_stmt = select(func.count()).select_from(threat_alerts_table).where(threat_alerts_table.c.status == "ACTIVE")
            active_alerts_count = conn.execute(active_stmt).scalar() or 0

            alerts_payload = []
            for a in recent_alerts:
                rule_name = a.get("rule_name") or a.get("threat_type") or "SECURITY_ALERT"
                score = a.get("threat_score", 0.0)
                if score == 0:
                    score, _ = ThreatScorer.calculate_score([rule_name])
                    if score == 0:
                        score = 90.0 if a.get("severity") == "CRITICAL" else 50.0

                ts = a.get("timestamp")
                alerts_payload.append({
                    "id": a["id"],
                    "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                    "log_id": a.get("log_id"),
                    "severity": a["severity"],
                    "rule_name": rule_name,
                    "threat_type": rule_name,
                    "threat_score": score,
                    "source_ip": a.get("source_ip"),
                    "description": a["description"],
                    "reasoning": a["description"],
                    "status": a.get("status", "ACTIVE")
                })

            logs_payload = []
            for l in reversed(recent_logs):
                l_ts = l.get("timestamp")
                logs_payload.append({
                    "id": l["id"],
                    "timestamp": l_ts.isoformat() if isinstance(l_ts, datetime) else str(l_ts),
                    "source_ip": l["source_ip"],
                    "destination_ip": l["destination_ip"],
                    "source_port": l.get("source_port", 0),
                    "destination_port": l.get("destination_port", 80),
                    "protocol": l.get("protocol", "TCP"),
                    "action": l.get("action", "ALLOW"),
                    "bytes_transferred": l.get("bytes_transferred", 0),
                    "message": l.get("message")
                })

            initial_payload = {
                "event": "initial_state",
                "type": "INITIAL_STATE",
                "payload": {
                    "logs": logs_payload,
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
