import asyncio
import json
import requests
import websockets

API_BASE = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/logs"

async def test_realtime_threat_pipeline():
    print("Testing Step 10: Real-Time Threat Pipeline over WebSocket...")
    
    async with websockets.connect(WS_URL) as ws:
        # Receive initial state
        initial_raw = await ws.recv()
        initial_data = json.loads(initial_raw)
        assert initial_data.get("event") == "initial_state" or initial_data.get("type") == "INITIAL_STATE"
        print("✓ Connected to /ws/logs and received initial state payload")

        # Ingest attack log triggering SQL Injection rule
        attack_log = {
            "source_ip": "193.142.146.210",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": "HTTP",
            "action": "BLOCK",
            "bytes_transferred": 640,
            "message": "GET /api/admin?query=1 UNION SELECT username, password FROM users"
        }

        response = requests.post(f"{API_BASE}/api/ingest/log", json=attack_log)
        assert response.status_code == 200, f"Ingestion failed: {response.text}"
        res_json = response.json()
        assert res_json["alerts_triggered"] > 0
        print("✓ Log ingested via POST /api/ingest/log and triggered threat rule")

        # Capture WebSocket messages
        captured_events = []
        for _ in range(3):
            try:
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                msg_json = json.loads(msg_raw)
                captured_events.append(msg_json)
            except asyncio.TimeoutError:
                break

        # Verify threat_alert event
        threat_alerts = [e for e in captured_events if e.get("event") == "threat_alert"]
        assert len(threat_alerts) > 0, "No 'threat_alert' event emitted over WebSocket!"

        alert_payload = threat_alerts[0].get("payload", threat_alerts[0].get("data", {}))
        assert "threat_score" in alert_payload, "Alert payload missing 'threat_score'"
        assert "reasoning" in alert_payload or "description" in alert_payload, "Alert payload missing 'reasoning'/'description'"
        assert alert_payload["source_ip"] == "193.142.146.210"
        
        print(f"✓ WebSocket Threat Alert received immediately!")
        print(f"  - Threat Type: {alert_payload.get('threat_type')}")
        print(f"  - Threat Score: {alert_payload.get('threat_score')}")
        print(f"  - Severity: {alert_payload.get('severity')}")
        print(f"  - Reasoning: {alert_payload.get('reasoning')}")

        # Verify Database Persistence via GET /api/alerts
        res_alerts = requests.get(f"{API_BASE}/api/alerts?limit=5")
        assert res_alerts.status_code == 200
        recent_alerts = res_alerts.json()
        matching_db_alerts = [a for a in recent_alerts if a["source_ip"] == "193.142.146.210"]
        assert len(matching_db_alerts) > 0, "Alert not found in database!"
        print("✓ Threat Alert confirmed stored persistently in database!")

if __name__ == "__main__":
    asyncio.run(test_realtime_threat_pipeline())
