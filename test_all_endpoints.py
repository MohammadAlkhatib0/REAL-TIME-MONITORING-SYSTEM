import requests

API_BASE = "http://127.0.0.1:8000"

def test_checklist_api_endpoints():
    print("==================================================")
    print("VERIFYING ALL MANDATORY API ENDPOINTS IN CHECKLIST")
    print("==================================================")

    # 1. Real-time Monitoring Endpoints
    # POST /api/ingest/log
    res_ingest = requests.post(f"{API_BASE}/api/ingest/log", json={
        "source_ip": "198.51.100.44",
        "destination_ip": "10.0.0.1",
        "protocol": "HTTP",
        "action": "ALLOW",
        "message": "GET /dashboard HTTP/1.1"
    })
    assert res_ingest.status_code == 200
    print("✓ POST /api/ingest/log PASSED")

    # GET /api/logs/recent
    res_logs = requests.get(f"{API_BASE}/api/logs/recent?limit=5")
    assert res_logs.status_code == 200
    print(f"✓ GET /api/logs/recent PASSED ({len(res_logs.json())} logs retrieved)")

    # 2. Threat Detection Endpoints
    # GET /api/threats
    res_threats = requests.get(f"{API_BASE}/api/threats?limit=5")
    assert res_threats.status_code == 200
    threats = res_threats.json()
    print(f"✓ GET /api/threats PASSED ({len(threats)} threats retrieved)")

    if len(threats) > 0:
        threat_id = threats[0]["id"]
        # GET /api/threats/{threat_id}
        res_single = requests.get(f"{API_BASE}/api/threats/{threat_id}")
        assert res_single.status_code == 200
        print(f"✓ GET /api/threats/{{threat_id}} PASSED (Threat #{threat_id})")

        # POST /api/threats/{threat_id}/resolve
        res_resolve = requests.post(f"{API_BASE}/api/threats/{threat_id}/resolve")
        assert res_resolve.status_code == 200
        assert res_resolve.json()["alert"]["status"] == "RESOLVED"
        print(f"✓ POST /api/threats/{{threat_id}}/resolve PASSED")

    # GET /api/threats/stats
    res_tstats = requests.get(f"{API_BASE}/api/threats/stats")
    assert res_tstats.status_code == 200
    print("✓ GET /api/threats/stats PASSED")

    # 3. Analytics Endpoints
    # GET /api/analytics/timeline
    res_time = requests.get(f"{API_BASE}/api/analytics/timeline?interval=1m&range=1h")
    assert res_time.status_code == 200
    print("✓ GET /api/analytics/timeline PASSED")

    # GET /api/analytics/top-sources
    res_top = requests.get(f"{API_BASE}/api/analytics/top-sources")
    assert res_top.status_code == 200
    print(f"✓ GET /api/analytics/top-sources PASSED ({len(res_top.json())} top sources)")

    # 4. IP Intelligence Endpoints
    # GET /api/ip/{ip_address}/info
    res_ip = requests.get(f"{API_BASE}/api/ip/198.51.100.44/info")
    assert res_ip.status_code == 200
    print("✓ GET /api/ip/{ip_address}/info PASSED")

    # POST /api/ip/blacklist
    res_bl = requests.post(f"{API_BASE}/api/ip/blacklist", json={"ip_address": "203.0.113.99"})
    assert res_bl.status_code == 200
    print("✓ POST /api/ip/blacklist PASSED")

    # 5. PF Sense Integration Endpoints
    # POST /api/ingest/pfsense
    pfsense_raw = "Feb 23 13:45:00 pfsense filterlog[123]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,80,0,S,10000,,"
    res_pf = requests.post(f"{API_BASE}/api/ingest/pfsense", data=pfsense_raw, headers={"Content-Type": "text/plain"})
    assert res_pf.status_code == 200
    print("✓ POST /api/ingest/pfsense PASSED")

    # GET /api/pfsense/firewall-rules
    res_pfrules = requests.get(f"{API_BASE}/api/pfsense/firewall-rules")
    assert res_pfrules.status_code == 200
    print("✓ GET /api/pfsense/firewall-rules PASSED")

    print("\n==================================================")
    print("ALL API CHECKLIST ENDPOINTS VERIFIED 100% SUCCESS!")
    print("==================================================")

if __name__ == "__main__":
    test_checklist_api_endpoints()
