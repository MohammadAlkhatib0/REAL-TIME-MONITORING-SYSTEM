import time
import random
import asyncio
import requests
from typing import Dict, Any, List

ATTACK_SCENARIOS = [
    {
        "name": "L7_DDOS_ATTACK",
        "description": "Layer 7 HTTP Flood on /api/v1/payments endpoint",
        "source_ips": ["193.142.146.210", "45.33.32.156", "185.220.101.5", "103.251.167.20"],
        "protocols": ["HTTPS", "HTTP"],
        "action": "ALLOW",
        "messages": [
            "GET /api/v1/payments?batch=99999 HTTP/2",
            "POST /api/v1/auth/token HTTP/2",
            "GET /api/v1/users/search?q=ddos_burst HTTP/1.1"
        ]
    },
    {
        "name": "CREDENTIAL_STUFFING",
        "description": "Automated Password Spraying against Admin SSO Portal",
        "source_ips": ["185.220.101.5", "116.203.11.89"],
        "protocols": ["HTTPS"],
        "action": "BLOCK",
        "messages": [
            "POST /auth/login - Failed password for admin@enterprise.com",
            "POST /auth/login - Failed password for root@enterprise.com",
            "POST /auth/login - 401 Unauthorized user=sysadmin"
        ]
    },
    {
        "name": "ZERO_DAY_SQL_INJECTION",
        "description": "SQL Injection & Schema Extraction Probe",
        "source_ips": ["193.142.146.210"],
        "protocols": ["HTTPS"],
        "action": "BLOCK",
        "messages": [
            "GET /api/v1/products?id=1 UNION SELECT 1, table_name, column_name FROM information_schema.columns",
            "POST /api/v1/orders - ' OR 1=1; DROP TABLE users; --"
        ]
    },
    {
        "name": "RANSOMWARE_C2_BEACON",
        "description": "Ransomware Command & Control Beaconing on Port 6667",
        "source_ips": ["45.33.32.156"],
        "protocols": ["TCP"],
        "action": "BLOCK",
        "messages": [
            "IRC C2 Beacon connection attempt to botnet.c2server.net:6667",
            "Encrypted Cobalt Strike payload beaconing detected"
        ]
    }
]

class EnterpriseSimulator:
    def __init__(self, api_url: str = "http://127.0.0.1:8000/api/ingest/log"):
        self.api_url = api_url
        self.is_running = False

    def generate_random_log(self) -> Dict[str, Any]:
        scenario = random.choice(ATTACK_SCENARIOS)
        src_ip = random.choice(scenario["source_ips"])
        msg = random.choice(scenario["messages"])
        protocol = random.choice(scenario["protocols"])
        
        return {
            "source_ip": src_ip,
            "destination_ip": "10.0.4.15",
            "source_port": random.randint(30000, 65535),
            "destination_port": 443 if protocol == "HTTPS" else 80,
            "protocol": protocol,
            "action": scenario["action"],
            "message": f"[{scenario['name']}] {msg}"
        }

    def inject_log_batch(self, count: int = 5):
        logs = [self.generate_random_log() for _ in range(count)]
        results = []
        for l in logs:
            try:
                res = requests.post(self.api_url, json=l, timeout=2.0)
                if res.status_code == 200:
                    results.append(res.json())
            except Exception:
                pass
        return len(results)

enterprise_simulator = EnterpriseSimulator()
