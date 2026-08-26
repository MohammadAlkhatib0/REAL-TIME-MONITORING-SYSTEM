import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Optional
from .schemas import LogCreate, AlertCreate
from .anomaly_detector import StatisticalAnomalyDetector

class ThreatDetectionEngine:
    def __init__(self):
        # Sliding windows for stateful detection (IP -> list of (timestamp, metadata))
        self.ip_port_window = defaultdict(lambda: deque())
        self.ip_failed_logins = defaultdict(lambda: deque())
        self.ip_request_window = defaultdict(lambda: deque())
        
        # Statistical Anomaly Detector
        self.anomaly_detector = StatisticalAnomalyDetector(window_size=30, interval_sec=1.0, z_score_threshold=3.0)

        # Debounce alerts to prevent spamming the exact same alert every second for same IP
        self.alert_cooldowns = {}

    def analyze_log(self, log: LogCreate) -> List[AlertCreate]:
        alerts: List[AlertCreate] = []
        now = time.time()
        src_ip = log.source_ip
        msg = log.message.lower() if log.message else ""

        # --- Rule 1: Malicious Payload Inspection (SQLi, XSS, Command Injection) ---
        sqli_patterns = [r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"select\s+\*\s+from"]
        xss_patterns = [r"<script>", r"javascript:", r"onerror\s*="]
        cmdi_patterns = [r"/etc/passwd", r"cmd\.exe", r"eval\(", r"system\("]

        matched_rule = None
        if any(re.search(p, msg) for p in sqli_patterns):
            matched_rule = ("SQL_INJECTION", "CRITICAL", f"SQL Injection attempt detected from {src_ip}: '{log.message}'")
        elif any(re.search(p, msg) for p in xss_patterns):
            matched_rule = ("XSS_ATTACK", "HIGH", f"Cross-Site Scripting (XSS) payload detected from {src_ip}: '{log.message}'")
        elif any(re.search(p, msg) for p in cmdi_patterns):
            matched_rule = ("COMMAND_INJECTION", "CRITICAL", f"Command Injection signature detected from {src_ip}: '{log.message}'")

        if matched_rule:
            rule_name, severity, description = matched_rule
            alerts.append(AlertCreate(
                timestamp=log.timestamp or datetime.utcnow(),
                severity=severity,
                rule_name=rule_name,
                source_ip=src_ip,
                description=description,
                status="ACTIVE"
            ))

        # --- Rule 2: Port Scanning Detection ---
        port_deque = self.ip_port_window[src_ip]
        port_deque.append((now, log.destination_port))
        while port_deque and port_deque[0][0] < now - 5.0:
            port_deque.popleft()
        
        unique_ports = {p[1] for p in port_deque}
        if len(unique_ports) >= 8:
            cooldown_key = f"PORT_SCAN_{src_ip}"
            if now - self.alert_cooldowns.get(cooldown_key, 0) > 10.0:
                self.alert_cooldowns[cooldown_key] = now
                alerts.append(AlertCreate(
                    timestamp=log.timestamp or datetime.utcnow(),
                    severity="HIGH",
                    rule_name="PORT_SCAN",
                    source_ip=src_ip,
                    description=f"Port Scan detected from {src_ip}: probed {len(unique_ports)} unique ports in 5s",
                    status="ACTIVE"
                ))

        # --- Rule 3: Brute Force Login Detection ---
        if log.action == "BLOCK" or "failed" in msg or "401" in msg or "403" in msg:
            fail_deque = self.ip_failed_logins[src_ip]
            fail_deque.append(now)
            while fail_deque and fail_deque[0] < now - 10.0:
                fail_deque.popleft()
            
            if len(fail_deque) >= 5:
                cooldown_key = f"BRUTE_FORCE_{src_ip}"
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 10.0:
                    self.alert_cooldowns[cooldown_key] = now
                    alerts.append(AlertCreate(
                        timestamp=log.timestamp or datetime.utcnow(),
                        severity="HIGH",
                        rule_name="BRUTE_FORCE",
                        source_ip=src_ip,
                        description=f"Possible Brute Force attack from {src_ip}: {len(fail_deque)} failed attempts in 10s",
                        status="ACTIVE"
                    ))

        # --- Rule 4: Traffic Spike / DDoS Detection ---
        req_deque = self.ip_request_window[src_ip]
        req_deque.append(now)
        while req_deque and req_deque[0] < now - 5.0:
            req_deque.popleft()

        if len(req_deque) >= 25:
            cooldown_key = f"DDOS_{src_ip}"
            if now - self.alert_cooldowns.get(cooldown_key, 0) > 10.0:
                self.alert_cooldowns[cooldown_key] = now
                alerts.append(AlertCreate(
                    timestamp=log.timestamp or datetime.utcnow(),
                    severity="CRITICAL",
                    rule_name="DDOS_ATTEMPT",
                    source_ip=src_ip,
                    description=f"High Traffic Volume / DDoS spike from {src_ip}: {len(req_deque)} requests in 5s",
                    status="ACTIVE"
                ))

        # --- Rule 5: Code-Based Statistical Anomaly Detection (> 3 Std Dev from Rolling Mean) ---
        anomaly_res = self.anomaly_detector.record_event(src_ip)
        if anomaly_res:
            alerts.append(AlertCreate(
                timestamp=log.timestamp or datetime.utcnow(),
                severity="HIGH",
                rule_name="TRAFFIC_ANOMALY",
                source_ip=src_ip,
                description=anomaly_res["description"],
                status="ACTIVE"
            ))

        return alerts

# Global instance for thread-safe memory state
threat_engine = ThreatDetectionEngine()
