import pytest
from backend.rules_engine import RuleEngine

def test_firmware_tampering_rule():
    engine = RuleEngine()
    current_log = {
        "device_id": "DEV-CAM-01",
        "action": "FIRMWARE_FLASH",
        "source_ip": "192.168.1.99",
        "target_port": 8080,
        "payload": "Unsigned image write"
    }
    match = engine.evaluate_log(current_log, [])
    assert match is not None
    assert match["category"] == "Firmware Tampering"
    assert match["severity"] == "Critical"

def test_config_tampering_rule():
    engine = RuleEngine()
    current_log = {
        "device_id": "DEV-LOCK-02",
        "action": "CONFIG_UPDATE",
        "source_ip": "192.168.1.88",
        "target_port": 443,
        "payload": "UNAUTHORIZED_CONFIG disable_security"
    }
    match = engine.evaluate_log(current_log, [])
    assert match is not None
    assert match["category"] == "Configuration Tampering"
    assert match["severity"] == "High"

def test_brute_force_rule_threshold():
    engine = RuleEngine()
    window = [
        {"source_ip": "10.0.0.5", "action": "AUTH_FAIL", "device_id": "DEV-01"} for _ in range(4)
    ]
    current = {"source_ip": "10.0.0.5", "action": "AUTH_FAIL", "device_id": "DEV-01"}
    
    match = engine.evaluate_log(current, window)
    assert match is not None
    assert match["category"] == "Brute Force Attack"

def test_port_scan_rule_threshold():
    engine = RuleEngine()
    window = [
        {"source_ip": "10.0.0.8", "action": "SYN_SCAN", "target_port": p} for p in [21, 22, 23, 80, 443, 8080]
    ]
    current = {"source_ip": "10.0.0.8", "action": "SYN_SCAN", "target_port": 9000}
    
    match = engine.evaluate_log(current, window)
    assert match is not None
    assert match["category"] == "Port Scanning"

def test_suspicious_ip_rule():
    engine = RuleEngine()
    current = {
        "device_id": "DEV-SENS-03",
        "action": "OUTBOUND_CONNECT",
        "source_ip": "198.51.100.99",
        "payload": "Telemetry output"
    }
    match = engine.evaluate_log(current, [])
    assert match is not None
    assert match["category"] == "Suspicious IP Communication"
