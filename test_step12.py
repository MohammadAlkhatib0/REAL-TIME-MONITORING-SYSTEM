import requests

API_BASE = "http://127.0.0.1:8000"

def test_pfsense_routes():
    print("Testing Step 12: pfSense Integration Routes...")

    # 1. POST /api/ingest/pfsense
    pfsense_raw_sample = "Feb 23 13:45:00 pfsense filterlog[123]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,80,0,S,10000,,"
    headers = {"Content-Type": "text/plain"}
    
    res1 = requests.post(f"{API_BASE}/api/ingest/pfsense", data=pfsense_raw_sample, headers=headers)
    assert res1.status_code == 200, f"POST /api/ingest/pfsense failed: {res1.text}"
    data1 = res1.json()
    assert data1["status"] == "success"
    parsed_log = data1["parsed_pfsense_log"]
    assert parsed_log["source_ip"] == "192.168.1.100"
    assert parsed_log["action"] == "BLOCK"
    assert parsed_log["rule_id"] == "1000000103"
    print("✓ POST /api/ingest/pfsense PASSED")
    print(f"  - Parsed Source IP: {parsed_log['source_ip']}")
    print(f"  - Action: {parsed_log['action']}")
    print(f"  - Rule ID: {parsed_log['rule_id']}")

    # 2. GET /api/pfsense/firewall-rules
    res2 = requests.get(f"{API_BASE}/api/pfsense/firewall-rules")
    assert res2.status_code == 200, f"GET /api/pfsense/firewall-rules failed: {res2.text}"
    rules = res2.json()
    assert isinstance(rules, list)
    assert len(rules) > 0
    assert "rule_id" in rules[0]
    assert "hit_count" in rules[0]
    print(f"✓ GET /api/pfsense/firewall-rules PASSED (Retrieved {len(rules)} rule stats)")
    for r in rules:
        print(f"  - Rule #{r['rule_id']} ({r['action']}): {r['hit_count']} hits - {r['description']}")

if __name__ == "__main__":
    test_pfsense_routes()
