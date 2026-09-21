import pytest
from backend.log_parser import LogParser

def test_parse_dict_log():
    raw_dict = {
        "device_id": "DEV-CAM-01",
        "device_type": "Smart Camera",
        "action": "AUTH_FAIL",
        "source_ip": "192.168.1.50",
        "target_port": 22,
        "payload": "Failed login attempt"
    }
    parsed = LogParser.parse_log(raw_dict)
    assert parsed["device_id"] == "DEV-CAM-01"
    assert parsed["log_type"] == "authentication"
    assert parsed["action"] == "AUTH_FAIL"
    assert parsed["target_port"] == 22

def test_parse_syslog_str():
    syslog_str = "2026-09-19T14:30:00 DEV-LOCK-02 CONFIG_UPDATE src=192.168.1.188 port=443 msg=System parameter modified"
    parsed = LogParser.parse_log(syslog_str)
    assert parsed["device_id"] == "DEV-LOCK-02"
    assert parsed["action"] == "CONFIG_UPDATE"
    assert parsed["source_ip"] == "192.168.1.188"
    assert parsed["target_port"] == 443

def test_log_type_inference():
    log_auth = LogParser.parse_log({"action": "USER_LOGIN_FAILED"})
    assert log_auth["log_type"] == "authentication"
    
    log_net = LogParser.parse_log({"action": "PORT_PROBE_CONNECT"})
    assert log_net["log_type"] == "network"
