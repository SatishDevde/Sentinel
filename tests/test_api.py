import pytest
from fastapi.testclient import TestClient
from backend.app import app, init_db

init_db()
client = TestClient(app)

def test_api_stats():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_logs" in data
    assert "active_threats" in data
    assert "total_devices" in data

def test_api_devices():
    res = client.get("/api/devices")
    assert res.status_code == 200
    devices = res.json()
    assert isinstance(devices, list)
    assert len(devices) > 0

def test_api_log_ingestion_and_threat():
    log_data = {
        "device_id": "DEV-LOCK-02",
        "device_type": "Smart Lock",
        "action": "FIRMWARE_FLASH",
        "source_ip": "192.168.1.199",
        "target_port": 8080,
        "payload": "Unsigned binary flash"
    }
    res = client.post("/api/logs/ingest", json=log_data)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["data"]["threat"] is not None
    assert body["data"]["threat"]["threat_category"] == "Firmware Tampering"

def test_api_simulation():
    res = client.post("/api/simulate", json={"scenario": "BRUTE_FORCE", "count": 3})
    assert res.status_code == 200
    body = res.json()
    assert body["logs_generated"] == 3
