from typing import List, Dict, Tuple, Any

# Rule Weights as specified in Step 8
RULE_WEIGHTS = {
    "BLACKLISTED_IP": 50,
    "FAILED_LOGINS_THRESHOLD": 30,
    "PORT_SCANNING": 40,
    "FIREWALL_BLOCK": 20
}

class ThreatScorer:
    """
    Threat Scoring System.
    Base Score = 0
    Rules Weights:
      - Blacklisted IP: +50
      - 5+ failed logins in 1 min: +30
      - Port scanning pattern: +40
      - Firewall block: +20

    Severity Levels:
      - 0  to 30: Low
      - 31 to 60: Medium
      - 61 to 80: High
      - 81 to 100: Critical
    """

    @staticmethod
    def calculate_score(triggered_rules: List[str]) -> Tuple[int, str]:
        """
        Calculates total score based on triggered rule keys and returns (total_score, severity_level).
        """
        score = 0
        normalized_rules = set()

        for r in triggered_rules:
            rule_key = str(r).upper().strip()
            if "BLACK" in rule_key or "LIST" in rule_key:
                normalized_rules.add("BLACKLISTED_IP")
            elif "LOGIN" in rule_key or "AUTH" in rule_key or "BRUTE" in rule_key:
                normalized_rules.add("FAILED_LOGINS_THRESHOLD")
            elif "PORT" in rule_key or "SCAN" in rule_key:
                normalized_rules.add("PORT_SCANNING")
            elif "FIREWALL" in rule_key or "BLOCK" in rule_key:
                normalized_rules.add("FIREWALL_BLOCK")

        for rule in normalized_rules:
            score += RULE_WEIGHTS.get(rule, 0)

        # Cap score at 100 max
        score = min(score, 100)

        # Determine Severity Level
        if score <= 30:
            severity = "Low"
        elif score <= 60:
            severity = "Medium"
        elif score <= 80:
            severity = "High"
        else:
            severity = "Critical"

        return score, severity

    @staticmethod
    def score_log_event(
        is_blacklisted: bool = False,
        has_5_failed_logins: bool = False,
        has_port_scan: bool = False,
        is_firewall_block: bool = False
    ) -> Dict[str, Any]:
        """
        Evaluates boolean rule flags for an event and returns a detailed scoring report dict.
        """
        triggered = []
        if is_blacklisted:
            triggered.append("BLACKLISTED_IP")
        if has_5_failed_logins:
            triggered.append("FAILED_LOGINS_THRESHOLD")
        if has_port_scan:
            triggered.append("PORT_SCANNING")
        if is_firewall_block:
            triggered.append("FIREWALL_BLOCK")

        score, severity = ThreatScorer.calculate_score(triggered)

        return {
            "base_score": 0,
            "total_score": score,
            "severity": severity,
            "triggered_rules": triggered,
            "score_breakdown": {
                r: RULE_WEIGHTS.get(r, 0) for r in triggered
            }
        }
