import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from backend.log_parser import LogParser

class TestLogParser(unittest.TestCase):
    def test_pfsense_parser(self):
        sample = "Feb 23 13:45:00 pfsense filterlog[123]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,80,0,S,10000,,"
        res = LogParser.parse(sample)
        self.assertEqual(res["format"], "pfsense")
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["event_type"], "firewall_block")
        self.assertEqual(res["source_ip"], "192.168.1.100")
        self.assertEqual(res["destination_ip"], "10.0.0.1")
        self.assertEqual(res["protocol"], "TCP")

    def test_auth_log_parser(self):
        sample = "Feb 23 13:45:00 authserver sshd[5678]: Failed password for invalid user admin from 192.168.1.50 port 42100 ssh2"
        res = LogParser.parse(sample)
        self.assertEqual(res["format"], "auth_log")
        self.assertEqual(res["action"], "BLOCK")
        self.assertEqual(res["event_type"], "auth_failure")
        self.assertEqual(res["source_ip"], "192.168.1.50")
        self.assertEqual(res["source_port"], 42100)
        self.assertEqual(res["severity"], "HIGH")

    def test_network_traffic_parser(self):
        sample = '192.168.1.20 - - [23/Aug/2026:13:45:00 +0000] "GET /api/v1/resource HTTP/1.1" 200 452'
        res = LogParser.parse(sample)
        self.assertEqual(res["format"], "network_traffic")
        self.assertEqual(res["action"], "ALLOW")
        self.assertEqual(res["source_ip"], "192.168.1.20")
        self.assertEqual(res["bytes_transferred"], 452)

    def test_simulated_parser(self):
        sample = {
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.1",
            "source_port": 51234,
            "destination_port": 80,
            "protocol": "HTTP",
            "action": "BLOCK",
            "event_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "message": "UNION SELECT * FROM admin_users"
        }
        res = LogParser.parse(sample)
        self.assertEqual(res["format"], "simulated_json")
        self.assertEqual(res["source_ip"], "45.33.32.156")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertEqual(res["action"], "BLOCK")

if __name__ == "__main__":
    unittest.main()
