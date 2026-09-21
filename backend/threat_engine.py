import uuid
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.rules_engine import RuleEngine
from backend.ml_engine import MLAnomalyDetector

class ThreatEngine:
    """
    Module 2 & Module 4 Core: Combined Threat Detection, Classification, 
    Severity Assignment, Evidence Formatting & Action Recommendations.
    """

    def __init__(self):
        self.rules_engine = RuleEngine()
        self.ml_detector = MLAnomalyDetector()

    def process_log(self, normalized_log: Dict[str, Any], recent_logs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Combines Rule-Based and ML outputs into a unified threat detection result.
        Returns a Threat Event dictionary if a threat/anomaly is detected, else None.
        """
        # 1. Rule-Based Evaluation
        rule_match = self.rules_engine.evaluate_log(normalized_log, recent_logs)
        
        # 2. ML Anomaly Evaluation
        is_ml_anomaly, ml_score = self.ml_detector.predict_anomaly(normalized_log)

        # If neither rule matched nor ML flagged anomaly, return None
        if not rule_match and not is_ml_anomaly:
            return None

        # Determine combined threat classification
        if rule_match:
            category = rule_match["category"]
            severity = rule_match["severity"]
            detection_method = "Hybrid (Rule + ML)" if is_ml_anomaly else "Rule-Based"
            matched_rule = rule_match["rule_id"]
            confidence = 0.95 if is_ml_anomaly else 0.88
            evidence_desc = rule_match["evidence"]
        else:
            category = "Abnormal Behavior (ML Flagged)"
            severity = "High" if ml_score > 0.75 else "Medium"
            detection_method = "Machine Learning Anomaly"
            matched_rule = "ML-ISOLATION-FOREST"
            confidence = round(ml_score, 2)
            evidence_desc = f"Statistical deviation from baseline behavior. Anomaly score: {ml_score}"

        recommended_actions = self._generate_recommended_actions(category, severity, normalized_log)

        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        
        threat_event = {
            "event_id": event_id,
            "timestamp": normalized_log["timestamp"],
            "device_id": normalized_log["device_id"],
            "device_name": normalized_log.get("device_name") or f"IoT Device ({normalized_log['device_id']})",
            "device_type": normalized_log["device_type"],
            "threat_category": category,
            "severity": severity,
            "detection_method": detection_method,
            "confidence_score": confidence,
            "anomaly_score": ml_score,
            "matched_rule": matched_rule,
            "source_ip": normalized_log["source_ip"],
            "target_port": normalized_log["target_port"],
            "evidence": json.dumps({
                "description": evidence_desc,
                "raw_message": normalized_log["raw_message"],
                "action": normalized_log["action"],
                "payload": normalized_log["payload"],
                "source_ip": normalized_log["source_ip"],
                "target_port": normalized_log["target_port"]
            }),
            "recommended_actions": json.dumps(recommended_actions),
            "status": "ACTIVE"
        }

        return threat_event

    @staticmethod
    def _generate_recommended_actions(category: str, severity: str, log: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Generates actionable, human-executable security recommendations based on threat type.
        """
        src_ip = log.get("source_ip", "source IP")
        dev_id = log.get("device_id", "device")
        
        actions = []

        if category == "Brute Force Attack":
            actions = [
                {"step": "1", "action": f"Temporarily isolate or block IP {src_ip} at edge gateway / firewall."},
                {"step": "2", "action": f"Force password reset & mandate MFA for accounts on device {dev_id}."},
                {"step": "3", "action": "Review authentication access logs for any successful compromise signs."}
            ]
        elif category == "Port Scanning":
            actions = [
                {"step": "1", "action": f"Add IP {src_ip} to rate-limiting / drop rules on network switch."},
                {"step": "2", "action": f"Verify open ports on device {dev_id} and close unnecessary services."},
                {"step": "3", "action": "Inspect network perimeter logs for related reconnaissance probes."}
            ]
        elif category == "DoS Attack":
            actions = [
                {"step": "1", "action": f"Activate SYN-proxy / ingress rate limiting for IP {src_ip}."},
                {"step": "2", "action": f"Verify CPU and memory usage on device {dev_id}."},
                {"step": "3", "action": "Reroute IoT management traffic to isolated VLAN."}
            ]
        elif category in ["Configuration Tampering", "Firmware Tampering"]:
            actions = [
                {"step": "1", "action": f"Isolate IoT device {dev_id} from primary production network segment."},
                {"step": "2", "action": "Perform cryptographic hash integrity verification on device firmware/configs."},
                {"step": "3", "action": "Restore verified golden backup configuration and update admin credentials."}
            ]
        elif category == "Suspicious IP Communication":
            actions = [
                {"step": "1", "action": f"Block outbound connections to external IP {src_ip} on DNS/Gateway filter."},
                {"step": "2", "action": f"Inspect active socket connections on {dev_id} for command & control (C2) signals."},
                {"step": "3", "action": "Run full malware/integrity scan on the affected IoT gateway."}
            ]
        else:
            actions = [
                {"step": "1", "action": f"Review recent operational telemetry logs on device {dev_id}."},
                {"step": "2", "action": f"Monitor traffic from {src_ip} for further escalation."},
                {"step": "3", "action": "Update ML baseline if behavior is confirmed legitimate operational variance."}
            ]

        return actions
