from typing import List, Dict, Any, Optional
import json

class RuleEngine:
    """
    Module 2: Rule-Based Threat Detection
    Evaluates normalized log streams against predefined security rules.
    """

    def __init__(self, rules_config: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules_config or self._default_rules()

    def _default_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": "RULE-BF-01",
                "name": "Repeated Failed Logins",
                "category": "Brute Force Attack",
                "severity": "High",
                "enabled": True,
                "type": "failed_login"
            },
            {
                "rule_id": "RULE-PS-01",
                "name": "Port Scanning Activity",
                "category": "Port Scanning",
                "severity": "Medium",
                "enabled": True,
                "type": "port_scan"
            },
            {
                "rule_id": "RULE-DOS-01",
                "name": "DoS Network Traffic Spike",
                "category": "DoS Attack",
                "severity": "Critical",
                "enabled": True,
                "type": "dos_traffic"
            },
            {
                "rule_id": "RULE-TMP-01",
                "name": "Unauthorized Configuration Change",
                "category": "Configuration Tampering",
                "severity": "High",
                "enabled": True,
                "type": "config_tampering"
            },
            {
                "rule_id": "RULE-FW-01",
                "name": "Firmware Modification Attempt",
                "category": "Firmware Tampering",
                "severity": "Critical",
                "enabled": True,
                "type": "firmware_tampering"
            },
            {
                "rule_id": "RULE-SIP-01",
                "name": "Suspicious IP Communication",
                "category": "Suspicious IP Communication",
                "severity": "High",
                "enabled": True,
                "type": "suspicious_ip"
            }
        ]

    def evaluate_log(self, current_log: Dict[str, Any], recent_logs_window: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Evaluates current log in context of recent logs window.
        Returns a threat match dictionary if a rule triggers, else None.
        """
        action = current_log.get("action", "").upper()
        payload = current_log.get("payload", "").upper()
        source_ip = current_log.get("source_ip", "")
        device_id = current_log.get("device_id", "")
        
        # 1. Firmware Tampering Check
        if any(act in action for act in ["FIRMWARE_FLASH", "BOOTLOADER_OVERWRITE", "TAMPER_FIRMWARE"]):
            return {
                "rule_id": "RULE-FW-01",
                "category": "Firmware Tampering",
                "severity": "Critical",
                "matched_rule": "Unauthorized firmware flash operation detected.",
                "evidence": f"Action '{action}' on device '{device_id}' from IP '{source_ip}'"
            }

        # 2. Configuration Tampering Check
        if any(act in action for act in ["CONFIG_UPDATE", "SET_PARAM", "DISABLE_SECURITY", "TAMPER_CONFIG"]) or "UNAUTHORIZED_CONFIG" in payload:
            return {
                "rule_id": "RULE-TMP-01",
                "category": "Configuration Tampering",
                "severity": "High",
                "matched_rule": "Configuration change without administrative clearance.",
                "evidence": f"Action '{action}' modified system configuration parameters on {device_id}."
            }

        # 3. Suspicious IP Communication
        suspicious_prefixes = ["198.51.100.", "203.0.113.", "45.33.32.", "185.220."]
        if any(source_ip.startswith(prefix) for prefix in suspicious_prefixes) or "MALICIOUS_IP" in payload:
            return {
                "rule_id": "RULE-SIP-01",
                "category": "Suspicious IP Communication",
                "severity": "High",
                "matched_rule": "Traffic initiated from untrusted/blacklisted IP range.",
                "evidence": f"Device {device_id} connected to flagged external IP {source_ip}."
            }

        # 4. Brute Force Detection (window evaluation)
        if "FAILED_LOGIN" in action or "AUTH_FAIL" in action or "INVALID_PASSWORD" in payload:
            failed_count = sum(
                1 for l in recent_logs_window 
                if l.get("source_ip") == source_ip and ("FAILED_LOGIN" in l.get("action", "") or "AUTH_FAIL" in l.get("action", "") or "INVALID_PASSWORD" in l.get("payload", ""))
            ) + 1
            if failed_count >= 5:
                return {
                    "rule_id": "RULE-BF-01",
                    "category": "Brute Force Attack",
                    "severity": "High",
                    "matched_rule": f"Failed login threshold exceeded ({failed_count} attempts).",
                    "evidence": f"Source IP {source_ip} targeted device {device_id} with {failed_count} failed logins."
                }

        # 5. Port Scan Detection (window evaluation)
        if "PORT_PROBE" in action or "SYN_SCAN" in action or "CONNECT_ATTEMPT" in action:
            unique_ports = set(
                l.get("target_port") for l in recent_logs_window 
                if l.get("source_ip") == source_ip and l.get("target_port") is not None
            )
            if current_log.get("target_port"):
                unique_ports.add(current_log["target_port"])
                
            if len(unique_ports) >= 6:
                return {
                    "rule_id": "RULE-PS-01",
                    "category": "Port Scanning",
                    "severity": "Medium",
                    "matched_rule": f"Rapid probing across {len(unique_ports)} distinct ports.",
                    "evidence": f"Source IP {source_ip} scanned ports: {sorted(list(unique_ports))[:10]} on {device_id}."
                }

        # 6. DoS Traffic Flood Detection
        if "TRAFFIC_FLOOD" in action or "PACKET_BURST" in action or "DOS_ATTEMPT" in action:
            same_src_logs = sum(1 for l in recent_logs_window if l.get("source_ip") == source_ip or l.get("device_id") == device_id) + 1
            if same_src_logs >= 15:
                return {
                    "rule_id": "RULE-DOS-01",
                    "category": "DoS Attack",
                    "severity": "Critical",
                    "matched_rule": "High volume packet flood exceeding standard rate limits.",
                    "evidence": f"{same_src_logs} rapid requests received from {source_ip} targeting {device_id}."
                }

        return None
