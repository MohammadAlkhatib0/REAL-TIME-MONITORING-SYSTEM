import time
from collections import defaultdict, deque
from typing import List, Dict, Any, Union

from threat_scorer import ThreatScorer

# Known Threat Intelligence Blacklisted IPs
DEFAULT_BLACKLISTED_IPS = {
    "45.33.32.156",
    "185.220.101.5",
    "193.142.146.210",
    "103.251.167.20",
    "192.168.1.666",
    "10.0.0.666"
}

# Sensitive / High-Risk Non-Standard Ports
UNUSUAL_PORTS = {23, 135, 139, 445, 1433, 1521, 3389, 5900, 6379, 6667, 27017}

class ThreatDetector:
    """
    Rules-Based Threat Detection Engine.
    Categories:
      1. Authentication Rules: Multiple failed logins (threshold: 5 in 1 min)
      2. Network Traffic Rules: Blacklisted IP connections, Unusual port access
      3. Firewall Rules: Repeated firewall blocks from same IP (threshold: 5 in 1 min)
    """

    def __init__(self, blacklisted_ips=None):
        self.blacklisted_ips = set(blacklisted_ips) if blacklisted_ips else set(DEFAULT_BLACKLISTED_IPS)
        
        # Sliding time windows for stateful threshold detection (ip -> deque of timestamps)
        self.failed_login_window = defaultdict(lambda: deque())
        self.firewall_block_window = defaultdict(lambda: deque())
        
        # Alert cooldown map to prevent duplicate alert spam for same IP (cooldown in seconds)
        self.alert_cooldowns = {}

    def analyze(self, log_entry: Union[Dict[str, Any], Any]) -> List[Dict[str, Any]]:
        """
        Analyzes a log entry dictionary and returns a list of triggered threat alerts.
        """
        # Normalize input to dictionary
        if hasattr(log_entry, "model_dump"):
            log_data = log_entry.model_dump()
        elif hasattr(log_entry, "__dict__"):
            log_data = log_entry.__dict__
        elif isinstance(log_entry, dict):
            log_data = log_entry
        else:
            log_data = {}

        alerts: List[Dict[str, Any]] = []

        # Extract normalized attributes
        source_ip = str(log_data.get("source_ip", "0.0.0.0")).strip()
        dest_port = int(log_data.get("destination_port", log_data.get("dst_port", 0)))
        action = str(log_data.get("action", "ALLOW")).upper()
        event_type = str(log_data.get("event_type", "")).lower()
        message = str(log_data.get("message", log_data.get("raw_message", ""))).lower()

        # 1. Check Authentication Rules
        auth_alerts = self.check_authentication_rules(source_ip, event_type, action, message)
        alerts.extend(auth_alerts)

        # 2. Check Network Traffic Rules
        network_alerts = self.check_network_traffic_rules(source_ip, dest_port)
        alerts.extend(network_alerts)

        # 3. Check Firewall Rules
        firewall_alerts = self.check_firewall_rules(source_ip, action, event_type)
        alerts.extend(firewall_alerts)

        return alerts

    def check_authentication_rules(self, source_ip: str, event_type: str, action: str, message: str) -> List[Dict[str, Any]]:
        """
        Authentication Rule: Multiple failed logins from same IP (threshold: 5 in 1 minute).
        """
        alerts = []
        now = time.time()

        is_auth_failure = (
            "auth_failure" in event_type or
            "failed" in message or
            "invalid user" in message or
            "401" in message or
            "403" in message or
            ("login" in message and action == "BLOCK")
        )

        if is_auth_failure:
            window = self.failed_login_window[source_ip]
            window.append(now)

            # Purge timestamps older than 60 seconds (1 minute window)
            while window and window[0] < now - 60.0:
                window.popleft()

            if len(window) >= 5:
                cooldown_key = f"AUTH_FAIL_{source_ip}"
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 15.0:
                    self.alert_cooldowns[cooldown_key] = now
                    alerts.append({
                        "threat_type": "MULTIPLE_FAILED_LOGINS",
                        "threat_score": 8.5,
                        "description": f"Authentication Rule Violation: {len(window)} failed login attempts from IP {source_ip} within 1 minute.",
                        "source_ip": source_ip,
                        "is_resolved": False
                    })

        return alerts

    def check_network_traffic_rules(self, source_ip: str, dest_port: int) -> List[Dict[str, Any]]:
        """
        Network Traffic Rules: Connections from blacklisted IPs, unusual port access.
        """
        alerts = []
        now = time.time()

        # Rule A: Blacklisted IP Detection
        if source_ip in self.blacklisted_ips:
            cooldown_key = f"BLACKLIST_{source_ip}"
            if now - self.alert_cooldowns.get(cooldown_key, 0) > 15.0:
                self.alert_cooldowns[cooldown_key] = now
                alerts.append({
                    "threat_type": "BLACK_LISTED_IP",
                    "threat_score": 9.0,
                    "description": f"Network Traffic Rule Violation: Connection attempt detected from blacklisted IP {source_ip}.",
                    "source_ip": source_ip,
                    "is_resolved": False
                })

        # Rule B: Unusual / Sensitive Port Access
        if dest_port in UNUSUAL_PORTS:
            cooldown_key = f"UNUSUAL_PORT_{source_ip}_{dest_port}"
            if now - self.alert_cooldowns.get(cooldown_key, 0) > 15.0:
                self.alert_cooldowns[cooldown_key] = now
                alerts.append({
                    "threat_type": "UNUSUAL_PORT_ACCESS",
                    "threat_score": 7.0,
                    "description": f"Network Traffic Rule Violation: Suspicious access attempt to sensitive/unusual port {dest_port} from IP {source_ip}.",
                    "source_ip": source_ip,
                    "is_resolved": False
                })

        return alerts

    def check_firewall_rules(self, source_ip: str, action: str, event_type: str) -> List[Dict[str, Any]]:
        """
        Firewall Rules: Repeated firewall blocks from same IP (threshold: 5 in 1 minute).
        """
        alerts = []
        now = time.time()

        if action == "BLOCK" or "block" in event_type:
            window = self.firewall_block_window[source_ip]
            window.append(now)

            # Purge timestamps older than 60 seconds (1 minute window)
            while window and window[0] < now - 60.0:
                window.popleft()

            if len(window) >= 5:
                cooldown_key = f"FW_BLOCK_{source_ip}"
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 15.0:
                    self.alert_cooldowns[cooldown_key] = now
                    alerts.append({
                        "threat_type": "REPEATED_FIREWALL_BLOCKS",
                        "threat_score": 8.0,
                        "description": f"Firewall Rule Violation: Repeated firewall blocks ({len(window)} blocks) from IP {source_ip} within 1 minute.",
                        "source_ip": source_ip,
                        "is_resolved": False
                    })

        return alerts
