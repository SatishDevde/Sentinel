import pytest
from backend.threat_engine import ThreatEngine

def test_threat_engine_processing():
    engine = ThreatEngine()
    log = {
        "log_id": "LOG-TEST-123",
        "timestamp": "2026-09-19T14:35:00",
        "device_id": "DEV-CAM-01",
        "device_type": "Smart Camera",
        "log_type": "authentication",
        "log_level": "WARNING",
        "source_ip": "10.0.0.45",
        "target_port": 22,
        "action": "AUTH_FAIL",
        "payload": "Failed password for root",
        "raw_message": "DEV-CAM-01 AUTH_FAIL src=185.220.101.45 port=22"
    }
    
    window = [log for _ in range(5)]
    threat = engine.process_log(log, window)
    
    assert threat is not None
    assert threat["device_id"] == "DEV-CAM-01"
    assert threat["threat_category"] == "Brute Force Attack"
    assert len(threat["recommended_actions"]) > 0
