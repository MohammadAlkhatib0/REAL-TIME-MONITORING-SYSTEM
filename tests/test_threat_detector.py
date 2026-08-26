import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from backend.threat_detector import ThreatDetector

class TestThreatDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ThreatDetector()

    def test_authentication_rule_failed_logins(self):
        attacker_ip = "192.168.1.50"
        alerts_triggered = []
        
        for i in range(5):
            log = {
                "source_ip": attacker_ip,
                "event_type": "auth_failure",
                "action": "ALLOW",  # Auth failure test
                "message": f"Failed password for user admin attempt #{i+1}"
            }
            alerts = self.detector.analyze(log)
            alerts_triggered.extend(alerts)

        threat_types = [a["threat_type"] for a in alerts_triggered]
        self.assertIn("MULTIPLE_FAILED_LOGINS", threat_types)
        
        auth_alert = [a for a in alerts_triggered if a["threat_type"] == "MULTIPLE_FAILED_LOGINS"][0]
        self.assertEqual(auth_alert["threat_score"], 8.5)
        self.assertIn("Authentication Rule Violation", auth_alert["description"])

    def test_network_traffic_rules(self):
        # Test 1: Blacklisted IP
        blacklisted_log = {
            "source_ip": "45.33.32.156",
            "destination_port": 80,
            "action": "ALLOW",
            "message": "GET /index.html"
        }
        alerts1 = self.detector.analyze(blacklisted_log)
        self.assertEqual(len(alerts1), 1)
        self.assertEqual(alerts1[0]["threat_type"], "BLACK_LISTED_IP")
        self.assertEqual(alerts1[0]["threat_score"], 9.0)

        # Test 2: Unusual Port Access (e.g. 3389 RDP)
        unusual_port_log = {
            "source_ip": "10.0.0.99",
            "destination_port": 3389,
            "action": "ALLOW",
            "message": "RDP Connection attempt"
        }
        alerts2 = self.detector.analyze(unusual_port_log)
        self.assertEqual(len(alerts2), 1)
        self.assertEqual(alerts2[0]["threat_type"], "UNUSUAL_PORT_ACCESS")
        self.assertEqual(alerts2[0]["threat_score"], 7.0)

    def test_firewall_rule_repeated_blocks(self):
        firewall_ip = "172.16.0.44"
        alerts_triggered = []

        for _ in range(5):
            log = {
                "source_ip": firewall_ip,
                "event_type": "firewall_block",
                "action": "BLOCK",
                "destination_port": 8080,
                "message": "pfSense filterlog block"
            }
            alerts = self.detector.analyze(log)
            alerts_triggered.extend(alerts)

        threat_types = [a["threat_type"] for a in alerts_triggered]
        self.assertIn("REPEATED_FIREWALL_BLOCKS", threat_types)
        
        fw_alert = [a for a in alerts_triggered if a["threat_type"] == "REPEATED_FIREWALL_BLOCKS"][0]
        self.assertEqual(fw_alert["threat_score"], 8.0)
        self.assertIn("Firewall Rule Violation", fw_alert["description"])

if __name__ == "__main__":
    unittest.main()
