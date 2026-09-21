import re
import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional

class LogParser:
    """
    Module 1: Log Collection & Normalization
    Parses and normalizes raw system, authentication, and network log entries from IoT devices.
    """
    
    @staticmethod
    def parse_log(raw_input: Any) -> Dict[str, Any]:
        """
        Parses raw dict, json string, or syslog string into a normalized log dictionary.
        """
        if isinstance(raw_input, dict):
            data = raw_input
        elif isinstance(raw_input, str):
            raw_input = raw_input.strip()
            if raw_input.startswith('{') and raw_input.endswith('}'):
                try:
                    data = json.loads(raw_input)
                except Exception:
                    data = LogParser._parse_text_log(raw_input)
            else:
                data = LogParser._parse_text_log(raw_input)
        else:
            raise ValueError("Unsupported log format")

        log_id = data.get("log_id") or f"LOG-{uuid.uuid4().hex[:8].upper()}"
        timestamp = data.get("timestamp") or datetime.now().isoformat()
        device_id = data.get("device_id") or "DEV-UNKNOWN"
        device_type = data.get("device_type") or "Generic IoT Device"
        log_type = data.get("log_type") or LogParser._infer_log_type(data)
        log_level = (data.get("log_level") or "INFO").upper()
        source_ip = data.get("source_ip") or "127.0.0.1"
        target_port = int(data.get("target_port") or 80)
        action = (data.get("action") or "UNKNOWN").upper()
        payload = str(data.get("payload") or "")
        raw_message = str(data.get("raw_message") or json.dumps(data))

        return {
            "log_id": log_id,
            "timestamp": timestamp,
            "device_id": device_id,
            "device_type": device_type,
            "log_type": log_type,
            "log_level": log_level,
            "source_ip": source_ip,
            "target_port": target_port,
            "action": action,
            "payload": payload,
            "raw_message": raw_message
        }

    @staticmethod
    def _parse_text_log(text: str) -> Dict[str, Any]:
        # Regex for common IoT Syslog pattern:
        # e.g., "2026-09-19T14:30:00 DEV-CAM-01 AUTH_FAIL src=192.168.1.50 port=22 msg=Failed password for admin"
        pattern = r'^(?P<timestamp>\S+)\s+(?P<device_id>\S+)\s+(?P<action>\S+)(?:\s+src=(?P<source_ip>\S+))?(?:\s+port=(?P<target_port>\d+))?(?:\s+msg=(?P<payload>.+))?'
        match = re.match(pattern, text)
        if match:
            gd = match.groupdict()
            return {
                "timestamp": gd.get("timestamp"),
                "device_id": gd.get("device_id"),
                "action": gd.get("action"),
                "source_ip": gd.get("source_ip") or "192.168.1.100",
                "target_port": int(gd.get("target_port") or 80),
                "payload": gd.get("payload") or text,
                "raw_message": text
            }
        return {
            "action": "RAW_EVENT",
            "payload": text,
            "raw_message": text
        }

    @staticmethod
    def _infer_log_type(data: Dict[str, Any]) -> str:
        action = str(data.get("action", "")).upper()
        payload = str(data.get("payload", "")).upper()
        
        auth_keywords = ["LOGIN", "AUTH", "PASSWORD", "USER", "CREDENTIAL", "TOKEN"]
        network_keywords = ["PORT", "CONNECT", "PACKET", "SYN", "FLOOD", "TRAFFIC", "HTTP", "TCP", "UDP"]
        
        if any(k in action or k in payload for k in auth_keywords):
            return "authentication"
        elif any(k in action or k in payload for k in network_keywords):
            return "network"
        return "system"
