from datetime import datetime
from typing import Dict, Any, Union
from log_parser import LogParser as MultiFormatParser
from .schemas import LogCreate

class LogParser:
    @staticmethod
    def parse_and_normalize(raw_data: Union[Dict[str, Any], str]) -> LogCreate:
        """
        Parses raw network logs (pfSense, Auth logs, Network Traffic, JSON simulated),
        extracting timestamps, source/destination IPs, ports, protocols, event types, actions, and messages.
        """
        parsed = MultiFormatParser.parse(raw_data)

        ts = parsed.get("timestamp")
        if not isinstance(ts, datetime):
            ts = datetime.utcnow()

        return LogCreate(
            timestamp=ts,
            source_ip=parsed.get("source_ip", "0.0.0.0"),
            destination_ip=parsed.get("destination_ip", "10.0.0.1"),
            source_port=parsed.get("source_port", 0),
            destination_port=parsed.get("destination_port", 80),
            protocol=parsed.get("protocol", "TCP"),
            action=parsed.get("action", "ALLOW"),
            bytes_transferred=parsed.get("bytes_transferred", 0),
            message=parsed.get("message", "")
        )
