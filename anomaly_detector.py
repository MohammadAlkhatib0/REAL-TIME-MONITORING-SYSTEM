import math
import time
from collections import defaultdict, deque
from typing import List, Dict, Any, Tuple, Optional

class StatisticalAnomalyDetector:
    """
    Code-Based Anomaly Detection Engine.
    - Tracks baseline traffic patterns per IP using sliding window logic.
    - Calculates moving average (mean) and standard deviation of connection frequency.
    - Flags IPs with activity > 3 standard deviations above the rolling mean.
    """

    def __init__(self, window_size: int = 30, interval_sec: float = 1.0, z_score_threshold: float = 3.0):
        self.window_size = window_size
        self.interval_sec = interval_sec
        self.z_score_threshold = z_score_threshold

        # IP -> sliding window history of interval request counts
        self.ip_window_history = defaultdict(lambda: deque(maxlen=self.window_size))
        
        # IP -> [interval_start_time, current_count]
        self.ip_current_interval = defaultdict(lambda: [time.time(), 0])
        
        # Alert cooldown map per IP
        self.alert_cooldowns = {}

    def record_event(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Records a connection event for a source IP, updates sliding window statistics,
        and checks if activity exceeds 3 standard deviations from the rolling mean.
        """
        now = time.time()
        interval_data = self.ip_current_interval[source_ip]
        interval_start, current_count = interval_data

        if now - interval_start >= self.interval_sec:
            # Shift interval to history
            if current_count > 0:
                self.ip_window_history[source_ip].append(current_count)
            self.ip_current_interval[source_ip] = [now, 1]
            current_count = 1
        else:
            current_count += 1
            self.ip_current_interval[source_ip][1] = current_count

        history = list(self.ip_window_history[source_ip])
        if len(history) < 3:
            return None

        mean, std_dev = self.calculate_stats(history)

        # Fallback minimum std_dev to 0.5 when baseline has 0 variance (constant traffic)
        effective_std_dev = max(std_dev, 0.5)

        if current_count > 4:
            z_score = (current_count - mean) / effective_std_dev
            if z_score >= self.z_score_threshold:
                cooldown_key = f"ANOMALY_{source_ip}"
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 10.0:
                    self.alert_cooldowns[cooldown_key] = now
                    threshold = mean + (self.z_score_threshold * effective_std_dev)
                    return {
                        "threat_type": "TRAFFIC_ANOMALY",
                        "threat_score": 85.0,
                        "description": (
                            f"Statistical Anomaly Detected: IP {source_ip} traffic spike ({current_count} req/interval) "
                            f"is > 3 std dev above rolling mean (Mean: {mean:.2f}, StdDev: {effective_std_dev:.2f}, Threshold: {threshold:.2f}, Z-Score: {z_score:.2f})."
                        ),
                        "source_ip": source_ip,
                        "current_rate": current_count,
                        "mean": round(mean, 2),
                        "std_dev": round(effective_std_dev, 2),
                        "z_score": round(z_score, 2),
                        "is_resolved": False
                    }

        return None

    @staticmethod
    def calculate_stats(data: List[int]) -> Tuple[float, float]:
        """
        Calculates moving average (mean) and standard deviation of a list of numeric values.
        """
        if not data:
            return 0.0, 0.0

        n = len(data)
        mean = sum(data) / n
        variance = sum((x - mean) ** 2 for x in data) / n
        std_dev = math.sqrt(variance)

        return mean, std_dev
