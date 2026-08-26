import re
import json
from datetime import datetime

class LogParser:
    """
    Multi-format Log Parser Service.
    Parses:
      1. pfSense Firewall Logs
      2. System Auth Logs (Failed / Accepted Logins)
      3. Network Traffic Logs (Syslog / Apache / NetFlow JSON)
      4. Custom Simulated Log Format
    Extracts:
      - Timestamp
      - Source IP / Source Port
      - Destination IP / Destination Port
      - Event Type (login_failure, firewall_block, connection, etc.)
      - Severity Level (CRITICAL, HIGH, MEDIUM, LOW)
      - Action (ALLOW, BLOCK, FLAG)
      - Rule ID (for pfSense firewall rules)
    """

    @staticmethod
    def parse_pfsense(log_str: str) -> dict:
        """
        Parses pfSense filterlog format.
        Example: Feb 23 13:45:00 pfsense filterlog[123]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,54321,80,0,S,10000,,
        """
        parts = log_str.split("filterlog")
        ts_part = parts[0].strip() if len(parts) > 1 else ""
        ts = LogParser._parse_syslog_timestamp(ts_part)

        csv_part = parts[1] if len(parts) > 1 else log_str
        fields = csv_part.split(",")

        action = "BLOCK" if "block" in log_str.lower() else "ALLOW"
        severity = "HIGH" if action == "BLOCK" else "LOW"
        event_type = "firewall_block" if action == "BLOCK" else "firewall_pass"

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        protocol = "TCP"
        rule_id = "1000000103"  # Default pfSense rule ID fallback

        # Extract Rule ID if available in 4th CSV field (e.g. 4,,,1000000103,em0...)
        if len(fields) >= 4 and fields[3].strip().isdigit():
            rule_id = fields[3].strip()

        # Look for IP patterns in CSV fields
        ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        ips_found = [f.strip() for f in fields if re.match(ip_regex, f.strip())]
        if len(ips_found) >= 2:
            src_ip = ips_found[0]
            dst_ip = ips_found[1]

        # Extract protocol and ports if available
        if "tcp" in log_str.lower():
            protocol = "TCP"
        elif "udp" in log_str.lower():
            protocol = "UDP"
        elif "icmp" in log_str.lower():
            protocol = "ICMP"

        numeric_fields = [int(f) for f in fields if f.strip().isdigit() and 1 <= int(f) <= 65535]
        if len(numeric_fields) >= 2:
            src_port = numeric_fields[-2]
            dst_port = numeric_fields[-1]

        return {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "action": action,
            "event_type": event_type,
            "severity": severity,
            "bytes_transferred": 64,
            "rule_id": rule_id,
            "message": log_str.strip(),
            "format": "pfsense"
        }

    @staticmethod
    def parse_auth_log(log_str: str) -> dict:
        ts = LogParser._parse_syslog_timestamp(log_str)
        is_failed = "failed" in log_str.lower() or "invalid" in log_str.lower() or "denied" in log_str.lower()

        event_type = "auth_failure" if is_failed else "auth_success"
        action = "BLOCK" if is_failed else "ALLOW"
        severity = "HIGH" if is_failed else "LOW"

        ip_match = re.search(r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log_str)
        src_ip = ip_match.group(1) if ip_match else "0.0.0.0"

        port_match = re.search(r"port\s+(\d+)", log_str)
        src_port = int(port_match.group(1)) if port_match else 22

        return {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": "10.0.0.1",
            "source_port": src_port,
            "destination_port": 22,
            "protocol": "SSH",
            "action": action,
            "event_type": event_type,
            "severity": severity,
            "bytes_transferred": 256,
            "message": log_str.strip(),
            "format": "auth_log"
        }

    @staticmethod
    def parse_network_traffic(log_str: str) -> dict:
        ip_match = re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log_str)
        src_ip = ip_match.group(1) if ip_match else "127.0.0.1"

        status_match = re.search(r'"\s+(\d{3})\s+(\d+|-)', log_str)
        status_code = int(status_match.group(1)) if status_match else 200
        bytes_tx = int(status_match.group(2)) if status_match and status_match.group(2).isdigit() else 512

        is_error = status_code >= 400
        action = "BLOCK" if is_error else "ALLOW"
        severity = "MEDIUM" if status_code >= 500 else ("LOW" if status_code < 400 else "MEDIUM")

        return {
            "timestamp": datetime.utcnow(),
            "source_ip": src_ip,
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": "HTTP",
            "action": action,
            "event_type": "http_request",
            "severity": severity,
            "bytes_transferred": bytes_tx,
            "message": log_str.strip(),
            "format": "network_traffic"
        }

    @staticmethod
    def parse_simulated(raw: dict | str) -> dict:
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                src_ip = "0.0.0.0"
                ip_match = re.search(r"SRC:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw)
                if ip_match:
                    src_ip = ip_match.group(1)
                return {
                    "timestamp": datetime.utcnow(),
                    "source_ip": src_ip,
                    "destination_ip": "10.0.0.1",
                    "source_port": 1024,
                    "destination_port": 80,
                    "protocol": "TCP",
                    "action": "ALLOW",
                    "event_type": "simulated_event",
                    "severity": "LOW",
                    "bytes_transferred": 100,
                    "message": raw.strip(),
                    "format": "simulated_string"
                }

        ts = raw.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                ts = datetime.utcnow()
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        src_ip = str(raw.get("source_ip", raw.get("src_ip", "0.0.0.0"))).strip()
        dst_ip = str(raw.get("destination_ip", raw.get("dst_ip", "10.0.0.1"))).strip()
        src_port = int(raw.get("source_port", raw.get("src_port", 0)))
        dst_port = int(raw.get("destination_port", raw.get("dst_port", 80)))
        protocol = str(raw.get("protocol", raw.get("proto", "TCP"))).upper()
        action = str(raw.get("action", "ALLOW")).upper()
        event_type = str(raw.get("event_type", "connection"))
        severity = str(raw.get("severity", "LOW" if action == "ALLOW" else "HIGH")).upper()
        bytes_tx = int(raw.get("bytes_transferred", raw.get("bytes", 0)))
        message = str(raw.get("message", ""))
        rule_id = str(raw.get("rule_id", "1000000103"))

        return {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "action": action,
            "event_type": event_type,
            "severity": severity,
            "bytes_transferred": bytes_tx,
            "rule_id": rule_id,
            "message": message,
            "format": "simulated_json"
        }

    @staticmethod
    def parse(raw_log: str | dict) -> dict:
        if isinstance(raw_log, dict):
            return LogParser.parse_simulated(raw_log)

        log_str = str(raw_log).strip()

        if "filterlog" in log_str:
            return LogParser.parse_pfsense(log_str)
        elif "sshd" in log_str or "auth" in log_str or "Failed password" in log_str:
            return LogParser.parse_auth_log(log_str)
        elif log_str.startswith("{") and log_str.endswith("}"):
            return LogParser.parse_simulated(log_str)
        elif re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", log_str):
            return LogParser.parse_network_traffic(log_str)
        else:
            return LogParser.parse_simulated(log_str)

    @staticmethod
    def _parse_syslog_timestamp(text: str) -> datetime:
        match = re.search(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", text)
        if match:
            try:
                date_str = f"{match.group(1)} {datetime.utcnow().year}"
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                pass
        return datetime.utcnow()
