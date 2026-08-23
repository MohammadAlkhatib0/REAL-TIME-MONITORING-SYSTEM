import unittest
from threat_scorer import ThreatScorer

class TestThreatScorer(unittest.TestCase):
    def test_low_severity_scores(self):
        # 1. Base score 0 -> Low (0-30)
        score, severity = ThreatScorer.calculate_score([])
        self.assertEqual(score, 0)
        self.assertEqual(severity, "Low")

        # 2. Firewall block (+20) -> Low
        res = ThreatScorer.score_log_event(is_firewall_block=True)
        self.assertEqual(res["total_score"], 20)
        self.assertEqual(res["severity"], "Low")

        # 3. 5+ failed logins (+30) -> Low
        res2 = ThreatScorer.score_log_event(has_5_failed_logins=True)
        self.assertEqual(res2["total_score"], 30)
        self.assertEqual(res2["severity"], "Low")

    def test_medium_severity_scores(self):
        # 1. Port scanning (+40) -> Medium (31-60)
        res1 = ThreatScorer.score_log_event(has_port_scan=True)
        self.assertEqual(res1["total_score"], 40)
        self.assertEqual(res1["severity"], "Medium")

        # 2. Blacklisted IP (+50) -> Medium
        res2 = ThreatScorer.score_log_event(is_blacklisted=True)
        self.assertEqual(res2["total_score"], 50)
        self.assertEqual(res2["severity"], "Medium")

        # 3. Firewall block (+20) + 5+ failed logins (+30) = 50 -> Medium
        res3 = ThreatScorer.score_log_event(is_firewall_block=True, has_5_failed_logins=True)
        self.assertEqual(res3["total_score"], 50)
        self.assertEqual(res3["severity"], "Medium")

    def test_high_severity_scores(self):
        # 1. Blacklisted IP (+50) + Firewall block (+20) = 70 -> High (61-80)
        res1 = ThreatScorer.score_log_event(is_blacklisted=True, is_firewall_block=True)
        self.assertEqual(res1["total_score"], 70)
        self.assertEqual(res1["severity"], "High")

        # 2. Port scanning (+40) + 5+ failed logins (+30) = 70 -> High
        res2 = ThreatScorer.score_log_event(has_port_scan=True, has_5_failed_logins=True)
        self.assertEqual(res2["total_score"], 70)
        self.assertEqual(res2["severity"], "High")

    def test_critical_severity_scores(self):
        # 1. Blacklisted IP (+50) + Port scanning (+40) = 90 -> Critical (81-100)
        res1 = ThreatScorer.score_log_event(is_blacklisted=True, has_port_scan=True)
        self.assertEqual(res1["total_score"], 90)
        self.assertEqual(res1["severity"], "Critical")

        # 2. All rules triggered (+50 +30 +40 +20 = 140 -> Capped at 100) -> Critical
        res2 = ThreatScorer.score_log_event(
            is_blacklisted=True,
            has_5_failed_logins=True,
            has_port_scan=True,
            is_firewall_block=True
        )
        self.assertEqual(res2["total_score"], 100)
        self.assertEqual(res2["severity"], "Critical")

if __name__ == "__main__":
    unittest.main()
