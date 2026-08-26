"""
Enterprise SIEM (Security Information and Event Management) Exporter
Formats and streams threat alerts to Splunk HEC, Elasticsearch, Datadog, and CEF Syslog.
"""

from typing import Dict, Any
import json
from datetime import datetime

class SIEMExporter:
    @staticmethod
    def to_cef(alert_data: Dict[str, Any]) -> str:
        """
        Converts alert payload into ArcSight Common Event Format (CEF)
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        severity_num = 10 if alert_data.get("severity") == "CRITICAL" else (7 if alert_data.get("severity") == "HIGH" else 4)
        cef_str = (
            f"CEF:0|CyberSentinel|EnterpriseSIEM|1.0|"
            f"{alert_data.get('threat_type', 'GENERIC_THREAT')}|"
            f"{alert_data.get('description', 'Threat Detected')}|"
            f"{severity_num}|"
            f"src={alert_data.get('source_ip', '0.0.0.0')} "
            f"score={alert_data.get('threat_score', 0)} "
            f"cat={alert_data.get('severity', 'LOW')}"
        )
        return cef_str

    @staticmethod
    def to_splunk_hec(alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formats alert for Splunk HTTP Event Collector (HEC)
        """
        return {
            "time": datetime.utcnow().timestamp(),
            "host": "cybersentinel-core-01",
            "source": "threat-detection-engine",
            "sourcetype": "_json",
            "event": alert_data
        }

    @staticmethod
    def to_elastic_bulk(alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formats alert for Elasticsearch / Kibana index
        """
        return {
            "_index": "cybersentinel-alerts-v1",
            "_doc": alert_data
        }

siem_exporter = SIEMExporter()
