import random
import time
from datetime import datetime
from typing import Dict, Any, List

class IoTSimulator:
    """
    IoT Log and Threat Event Simulator for controlled security evaluation.
    Simulates real-world IoT device telemetry and attack scenarios.
    """

    DEVICES = [
        {"id": "DEV-CAM-01", "type": "Smart Camera", "ip": "192.168.1.101"},
        {"id": "DEV-LOCK-02", "type": "Smart Lock", "ip": "192.168.1.102"},
        {"id": "DEV-SENS-03", "type": "Industrial Sensor", "ip": "192.168.1.103"},
        {"id": "DEV-GTW-04", "type": "IoT Gateway", "ip": "192.168.1.1"},
        {"id": "DEV-CAM-05", "type": "Smart Camera", "ip": "192.168.1.105"},
        {"id": "DEV-LOCK-06", "type": "Smart Lock", "ip": "192.168.1.106"}
    ]

    ATTACK_TYPES = [
        "BRUTE_FORCE",
        "PORT_SCAN",
        "DOS_FLOOD",
        "CONFIG_TAMPER",
        "FIRMWARE_TAMPER",
        "SUSPICIOUS_IP",
        "NORMAL"
    ]

    @staticmethod
    def generate_single_log(scenario: str = "AUTO") -> Dict[str, Any]:
        """Generates a simulated log entry based on requested scenario."""
        if scenario == "AUTO":
            # 70% normal, 30% attack
            scenario = random.choices(
                IoTSimulator.ATTACK_TYPES, 
                weights=[10, 10, 8, 8, 5, 8, 51]
            )[0]

        dev = random.choice(IoTSimulator.DEVICES)
        now_str = datetime.now().isoformat()
        
        if scenario == "BRUTE_FORCE":
            attacker_ip = "185.220.101.45"
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "authentication",
                "log_level": "WARNING",
                "source_ip": attacker_ip,
                "target_port": 22,
                "action": "AUTH_FAIL",
                "payload": "Failed SSH password for root from invalid credential attempt",
                "raw_message": f"{now_str} {dev['id']} AUTH_FAIL src={attacker_ip} port=22 msg=Failed password for root"
            }
            
        elif scenario == "PORT_SCAN":
            attacker_ip = "45.33.32.15"
            port = random.choice([21, 22, 23, 80, 443, 502, 1883, 8080, 9000, 3389])
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "network",
                "log_level": "WARNING",
                "source_ip": attacker_ip,
                "target_port": port,
                "action": "SYN_SCAN",
                "payload": f"TCP SYN packet sent to target port {port}",
                "raw_message": f"{now_str} {dev['id']} SYN_SCAN src={attacker_ip} port={port} msg=Recon probe"
            }
            
        elif scenario == "DOS_FLOOD":
            attacker_ip = "198.51.100.88"
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "network",
                "log_level": "CRITICAL",
                "source_ip": attacker_ip,
                "target_port": 80,
                "action": "TRAFFIC_FLOOD",
                "payload": "High volume UDP flood exceeding bandwidth limits: 5000 pkts/sec",
                "raw_message": f"{now_str} {dev['id']} TRAFFIC_FLOOD src={attacker_ip} port=80 msg=Bandwidth limit breached"
            }

        elif scenario == "CONFIG_TAMPER":
            attacker_ip = "192.168.1.188"
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "system",
                "log_level": "WARNING",
                "source_ip": attacker_ip,
                "target_port": 443,
                "action": "CONFIG_UPDATE",
                "payload": "Unauthorized change to system configuration parameters: SET_PARAM disable_encryption=1",
                "raw_message": f"{now_str} {dev['id']} CONFIG_UPDATE src={attacker_ip} port=443 msg=System parameter altered"
            }

        elif scenario == "FIRMWARE_TAMPER":
            attacker_ip = "192.168.1.199"
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "system",
                "log_level": "CRITICAL",
                "source_ip": attacker_ip,
                "target_port": 8080,
                "action": "FIRMWARE_FLASH",
                "payload": "Unsigned binary bootloader image flash requested without RSA validation",
                "raw_message": f"{now_str} {dev['id']} FIRMWARE_FLASH src={attacker_ip} port=8080 msg=Unsigned bootloader write"
            }

        elif scenario == "SUSPICIOUS_IP":
            attacker_ip = "203.0.113.77"
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": "network",
                "log_level": "WARNING",
                "source_ip": attacker_ip,
                "target_port": 1883,
                "action": "OUTBOUND_CONNECT",
                "payload": "MQTT broker session established with untrusted external relay host",
                "raw_message": f"{now_str} {dev['id']} OUTBOUND_CONNECT src={attacker_ip} port=1883 msg=Untrusted host connection"
            }

        else: # NORMAL
            return {
                "timestamp": now_str,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "log_type": random.choice(["system", "network"]),
                "log_level": "INFO",
                "source_ip": dev["ip"],
                "target_port": random.choice([80, 443, 1883]),
                "action": random.choice(["HEARTBEAT", "TELEMETRY_SYNC", "STATUS_CHECK"]),
                "payload": f"Normal operational telemetry payload temp=24.5C humidity=45% uptime={random.randint(100, 5000)}s",
                "raw_message": f"{now_str} {dev['id']} HEARTBEAT src={dev['ip']} port=1883 msg=Telemetry normal"
            }

    @staticmethod
    def generate_attack_burst(attack_type: str, count: int = 6) -> List[Dict[str, Any]]:
        """Generates a burst of attack logs for rapid threshold evaluation."""
        return [IoTSimulator.generate_single_log(attack_type) for _ in range(count)]
