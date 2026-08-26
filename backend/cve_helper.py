"""
CVE Vulnerability Mapper & MITRE ATT&CK TTP Intelligence Helper
Maps attack signatures to CVE identifiers, Risk Scores, and MITRE ATT&CK Tactics.
"""

MITRE_TTP_MAPPING = {
    "SQL_INJECTION": {
        "cve_id": "CVE-2023-34362",
        "cve_name": "MOVEit Transfer SQLi Remote Code Execution",
        "cvss_score": 9.8,
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access / Exploit Public-Facing Application",
        "description": "SQL Injection vulnerability allowing unauthenticated remote code execution and data exfiltration."
    },
    "COMMAND_INJECTION": {
        "cve_id": "CVE-2021-44228",
        "cve_name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "cvss_score": 10.0,
        "mitre_id": "T1059",
        "mitre_tactic": "Execution / Command and Scripting Interpreter",
        "description": "Unauthenticated remote code execution via log message string formatting injection."
    },
    "BRUTE_FORCE": {
        "cve_id": "CVE-2024-3094",
        "cve_name": "XZ Utils SSH Authentication Bypass",
        "cvss_score": 10.0,
        "mitre_id": "T1110",
        "mitre_tactic": "Credential Access / Brute Force & Password Spraying",
        "description": "Automated authentication attempt flood targeting SSH/HTTPS login endpoints."
    },
    "TRAFFIC_ANOMALY": {
        "cve_id": "CVE-2023-44487",
        "cve_name": "HTTP/2 Rapid Reset Volumetric DDoS Attack",
        "cvss_score": 7.5,
        "mitre_id": "T1498",
        "mitre_tactic": "Impact / Network Denial of Service",
        "description": "Volumetric layer 7 application flood exceeding baseline statistical thresholds."
    },
    "PORT_SCAN": {
        "cve_id": "CVE-2023-28252",
        "cve_name": "Windows Common Log File System Privilege Escalation",
        "cvss_score": 7.8,
        "mitre_id": "T1046",
        "mitre_tactic": "Reconnaissance / Network Service Discovery",
        "description": "Reconnaissance scan sweeping sensitive system ports for vulnerable service identification."
    }
}

def get_cve_mitre_info(rule_name: str) -> dict:
    rule_key = rule_name.upper()
    for key, data in MITRE_TTP_MAPPING.items():
        if key in rule_key:
            return data
    
    return {
        "cve_id": "CVE-2024-GENERIC",
        "cve_name": "Generic Network Threat Indicator",
        "cvss_score": 6.5,
        "mitre_id": "T1071",
        "mitre_tactic": "Command and Control / Application Layer Protocol",
        "description": "Uncategorized network anomaly or suspicious protocol pattern."
    }

def get_mitre_matrix_summary() -> list:
    return [
        {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application (T1190)",
            "mapped_rule": "SQL Injection / XSS",
            "severity": "CRITICAL",
            "detected_count": 156
        },
        {
            "tactic": "Credential Access",
            "technique": "Brute Force (T1110)",
            "mapped_rule": "Multiple Failed Logins",
            "severity": "HIGH",
            "detected_count": 42
        },
        {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter (T1059)",
            "mapped_rule": "Command Injection",
            "severity": "CRITICAL",
            "detected_count": 14
        },
        {
            "tactic": "Impact",
            "technique": "Network Denial of Service (T1498)",
            "mapped_rule": "Traffic Anomaly / L7 DDoS",
            "severity": "HIGH",
            "detected_count": 9
        },
        {
            "tactic": "Reconnaissance",
            "technique": "Network Service Discovery (T1046)",
            "mapped_rule": "Unusual Port Access / Port Scan",
            "severity": "MEDIUM",
            "detected_count": 28
        }
    ]
