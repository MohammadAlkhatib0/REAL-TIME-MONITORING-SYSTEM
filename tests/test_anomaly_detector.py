import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
import unittest
from backend.anomaly_detector import StatisticalAnomalyDetector

class TestStatisticalAnomalyDetector(unittest.TestCase):
    def test_calculate_stats_math(self):
        data = [10, 12, 10, 11, 9, 10]
        mean, std = StatisticalAnomalyDetector.calculate_stats(data)
        self.assertAlmostEqual(mean, 10.333, places=2)
        self.assertGreater(std, 0)

    def test_normal_baseline_no_anomaly(self):
        detector = StatisticalAnomalyDetector(window_size=10, interval_sec=0.05, z_score_threshold=3.0)
        target_ip = "192.168.1.10"

        for _ in range(5):
            detector.record_event(target_ip)
            detector.record_event(target_ip)
            time.sleep(0.06)

        alert = detector.record_event(target_ip)
        self.assertIsNone(alert)

    def test_statistical_spike_triggers_anomaly(self):
        detector = StatisticalAnomalyDetector(window_size=10, interval_sec=0.05, z_score_threshold=3.0)
        target_ip = "45.33.32.156"

        # Establish 5 normal baseline intervals
        for _ in range(5):
            detector.record_event(target_ip)
            detector.record_event(target_ip)
            time.sleep(0.06)

        # Trigger sudden massive traffic spike in current interval
        alert = None
        for _ in range(25):
            res = detector.record_event(target_ip)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["threat_type"], "TRAFFIC_ANOMALY")
        self.assertGreater(alert["z_score"], 3.0)
        self.assertIn("Statistical Anomaly Detected", alert["description"])

if __name__ == "__main__":
    unittest.main()
