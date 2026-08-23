import asyncio
import json
import requests
import websockets

API_BASE = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/logs"

def test_http_endpoints():
    print("Testing HTTP Endpoints...")
    
    # 1. POST /api/ingest/log
    sample_log = {
        "source_ip": "192.168.1.99",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "protocol": "TCP",
        "action": "ALLOW",
        "bytes_transferred": 128,
        "message": "HTTP GET /healthcheck"
    }
    
    res = requests.post(f"{API_BASE}/api/ingest/log", json=sample_log)
    assert res.status_code == 200, f"POST /api/ingest/log failed: {res.text}"
    body = res.json()
    assert body["status"] == "success"
    print("✓ POST /api/ingest/log PASSED")

    # 2. GET /api/logs/recent
    res_recent = requests.get(f"{API_BASE}/api/logs/recent?limit=10")
    assert res_recent.status_code == 200, f"GET /api/logs/recent failed: {res_recent.text}"
    recent = res_recent.json()
    assert isinstance(recent, list)
    assert len(recent) > 0
    print(f"✓ GET /api/logs/recent PASSED (retrieved {len(recent)} recent logs)")

async def test_websocket_endpoint():
    print("Testing WebSocket Endpoint /ws/logs...")
    async with websockets.connect(WS_URL) as ws:
        # Receive initial state
        initial_msg = await ws.recv()
        data = json.loads(initial_msg)
        assert data.get("event") == "initial_state" or data.get("type") == "INITIAL_STATE"
        print("✓ Connected to /ws/logs and received initial state event")

        # Ingest a log that triggers a threat alert to verify emission of new_log and threat_alert
        sqli_log = {
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.1",
            "source_port": 49152,
            "destination_port": 80,
            "protocol": "HTTP",
            "action": "BLOCK",
            "bytes_transferred": 500,
            "message": "GET /api/users?id=1 UNION SELECT username, password FROM admin"
        }
        
        requests.post(f"{API_BASE}/api/ingest/log", json=sqli_log)

        # Wait for new_log and threat_alert broadcasts
        events_received = set()
        for _ in range(3):
            try:
                raw_event = await asyncio.wait_for(ws.recv(), timeout=2.0)
                event_data = json.loads(raw_event)
                event_name = event_data.get("event")
                events_received.add(event_name)
            except asyncio.TimeoutError:
                break

        print(f"Events captured over WebSocket: {events_received}")
        assert "new_log" in events_received, "Missing 'new_log' event on WebSocket stream"
        assert "threat_alert" in events_received, "Missing 'threat_alert' event on WebSocket stream"
        print("✓ WebSocket /ws/logs emitted 'new_log' and 'threat_alert' events successfully!")

if __name__ == "__main__":
    test_http_endpoints()
    asyncio.run(test_websocket_endpoint())
