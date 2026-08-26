import requests

API_BASE = "http://127.0.0.1:8000"

def test_step11_routes():
    print("Testing Step 11 Threat Data Routes...")

    # 1. GET /api/threats
    res1 = requests.get(f"{API_BASE}/api/threats?limit=10")
    assert res1.status_code == 200, f"GET /api/threats failed: {res1.text}"
    threats = res1.json()
    assert isinstance(threats, list)
    print(f"✓ GET /api/threats PASSED (Retrieved {len(threats)} threats)")

    # 2. GET /api/threats/stats
    res2 = requests.get(f"{API_BASE}/api/threats/stats")
    assert res2.status_code == 200, f"GET /api/threats/stats failed: {res2.text}"
    stats = res2.json()
    assert "total_threats" in stats
    assert "active_threats" in stats
    assert "by_severity" in stats
    assert "by_type" in stats
    print("✓ GET /api/threats/stats PASSED")
    print(f"  - Total Threats: {stats['total_threats']}")
    print(f"  - By Severity: {stats['by_severity']}")
    print(f"  - By Type: {stats['by_type']}")

    # 3. GET /api/analytics/timeline
    res3 = requests.get(f"{API_BASE}/api/analytics/timeline?interval=1m&range=1h")
    assert res3.status_code == 200, f"GET /api/analytics/timeline failed: {res3.text}"
    timeline = res3.json()
    assert isinstance(timeline, list)
    assert len(timeline) > 0
    assert "timestamp" in timeline[0]
    assert "event_count" in timeline[0]
    assert "threat_count" in timeline[0]
    print(f"✓ GET /api/analytics/timeline PASSED (Retrieved {len(timeline)} timeline points)")

if __name__ == "__main__":
    test_step11_routes()
