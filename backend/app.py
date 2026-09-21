import os
import sys
import json
import sqlite3
import subprocess
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, get_db_connection
from backend.log_parser import LogParser
from backend.threat_engine import ThreatEngine
from backend.device_tracker import DeviceTracker
from backend.simulator import IoTSimulator

app = FastAPI(
    title="Sentinel - IoT Threat Detection & Log Analysis System",
    description="Centralized threat detection system combining Rule-Based Detection and Scikit-Learn Anomaly Detection for IoT devices.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
init_db()
threat_engine = ThreatEngine()
recent_logs_cache: List[Dict[str, Any]] = []

class LogIngestRequest(BaseModel):
    raw_log: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    log_type: Optional[str] = None
    log_level: Optional[str] = None
    source_ip: Optional[str] = None
    target_port: Optional[int] = None
    action: Optional[str] = None
    payload: Optional[str] = None

class SimulationRequest(BaseModel):
    scenario: str = "AUTO"  # BRUTE_FORCE, PORT_SCAN, DOS_FLOOD, CONFIG_TAMPER, FIRMWARE_TAMPER, SUSPICIOUS_IP, NORMAL, AUTO
    count: int = 5

class ThreatStatusUpdate(BaseModel):
    status: str # ACKNOWLEDGED, RESOLVED, ACTIVE

# Helper function to process log and record to DB
def process_and_store_log(raw_input: Any) -> Dict[str, Any]:
    global recent_logs_cache
    
    normalized = LogParser.parse_log(raw_input)
    
    # Store normalized log in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO iot_logs 
        (log_id, timestamp, device_id, device_type, log_type, log_level, source_ip, target_port, action, payload, raw_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        normalized["log_id"], normalized["timestamp"], normalized["device_id"], normalized["device_type"],
        normalized["log_type"], normalized["log_level"], normalized["source_ip"], normalized["target_port"],
        normalized["action"], normalized["payload"], normalized["raw_message"]
    ))
    conn.commit()
    conn.close()

    # Maintain sliding window cache of recent 50 logs for threshold calculations
    recent_logs_cache.append(normalized)
    if len(recent_logs_cache) > 50:
        recent_logs_cache.pop(0)

    # Register/update device
    DeviceTracker.register_or_update_device(
        normalized["device_id"], 
        normalized["device_type"], 
        normalized["source_ip"]
    )

    # Run combined Rule + ML Threat Detection
    threat = threat_engine.process_log(normalized, recent_logs_cache)
    
    if threat:
        # Save detected threat event to DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO threat_events 
            (event_id, timestamp, device_id, device_name, device_type, threat_category, severity, 
             detection_method, confidence_score, anomaly_score, matched_rule, source_ip, target_port, evidence, recommended_actions, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat["event_id"], threat["timestamp"], threat["device_id"], threat["device_name"],
            threat["device_type"], threat["threat_category"], threat["severity"], threat["detection_method"],
            threat["confidence_score"], threat["anomaly_score"], threat["matched_rule"], threat["source_ip"],
            threat["target_port"], threat["evidence"], threat["recommended_actions"], threat["status"]
        ))
        conn.commit()
        conn.close()

        # Update device risk score & status in Module 3
        DeviceTracker.record_threat_impact(threat["device_id"], threat["severity"])

    return {"log": normalized, "threat": threat}

@app.get("/api/stats")
def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM iot_logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM threat_events WHERE status = 'ACTIVE'")
    active_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM iot_devices")
    total_devices = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM iot_devices WHERE status IN ('CRITICAL', 'WARNING')")
    compromised_devices = cursor.fetchone()[0]
    
    cursor.execute("SELECT threat_category, COUNT(*) as count FROM threat_events GROUP BY threat_category")
    category_counts = {row["threat_category"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT severity, COUNT(*) as count FROM threat_events GROUP BY severity")
    severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}

    conn.close()
    
    return {
        "total_logs": total_logs,
        "active_threats": active_threats,
        "total_devices": total_devices,
        "compromised_devices": compromised_devices,
        "category_counts": category_counts,
        "severity_counts": severity_counts
    }

@app.post("/api/logs/ingest")
def ingest_log(body: Dict[str, Any]):
    try:
        raw_log = body.get("raw_log") or body
        result = process_and_store_log(raw_log)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/logs")
def get_logs(limit: int = 50, log_type: Optional[str] = None, device_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM iot_logs"
    params = []
    conditions = []
    
    if log_type:
        conditions.append("log_type = ?")
        params.append(log_type)
    if device_id:
        conditions.append("device_id = ?")
        params.append(device_id)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return logs

@app.get("/api/threats")
def get_threats(limit: int = 50, severity: Optional[str] = None, status: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM threat_events"
    params = []
    conditions = []
    
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if status:
        conditions.append("status = ?")
        params.append(status)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    threats = []
    for r in cursor.fetchall():
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
        d["recommended_actions"] = json.loads(d["recommended_actions"]) if d["recommended_actions"] else []
        threats.append(d)
        
    conn.close()
    return threats

@app.post("/api/threats/{event_id}/status")
def update_threat_status(event_id: str, body: ThreatStatusUpdate):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE threat_events SET status = ? WHERE event_id = ?", (body.status, event_id))
    conn.commit()
    conn.close()
    return {"status": "updated", "event_id": event_id, "new_status": body.status}

@app.get("/api/devices")
def get_devices():
    return DeviceTracker.get_all_devices()

@app.get("/api/devices/{device_id}")
def get_device_details(device_id: str):
    dev = DeviceTracker.get_device_by_id(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    timeline = DeviceTracker.get_device_activity_timeline(device_id)
    
    # parse json strings in timeline threats
    for t in timeline["threats"]:
        t["evidence"] = json.loads(t["evidence"]) if t.get("evidence") else {}
        t["recommended_actions"] = json.loads(t["recommended_actions"]) if t.get("recommended_actions") else []
        
    return {"device": dev, "timeline": timeline}

@app.post("/api/simulate")
def trigger_simulation(body: SimulationRequest):
    results = []
    if body.scenario in ["BRUTE_FORCE", "PORT_SCAN", "DOS_FLOOD"]:
        # generate burst
        logs = IoTSimulator.generate_attack_burst(body.scenario, body.count)
        for l in logs:
            results.append(process_and_store_log(l))
    else:
        for _ in range(body.count):
            l = IoTSimulator.generate_single_log(body.scenario)
            results.append(process_and_store_log(l))
            
    threats_count = sum(1 for r in results if r["threat"] is not None)
    return {
        "status": "success",
        "scenario": body.scenario,
        "logs_generated": len(results),
        "threats_detected": threats_count,
        "details": results
    }

@app.post("/api/tests/run")
def run_test_suite():
    """Executes pytest suite and returns pass/fail status and output."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        res = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"],
            cwd=project_root,
            capture_output=True,
            text=True
        )
        return {
            "exit_code": res.returncode,
            "success": res.returncode == 0,
            "stdout": res.stdout,
            "stderr": res.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# Serve frontend directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dir = os.path.join(project_root, "frontend")

if os.path.exists(frontend_dir):
    app.mount("/css", StaticFiles(directory=os.path.join(frontend_dir, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(frontend_dir, "js")), name="js")

@app.get("/")
def serve_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    # Fallback search if working directory differs in serverless container
    alt_index = os.path.join(os.getcwd(), "frontend", "index.html")
    if os.path.exists(alt_index):
        return FileResponse(alt_index)
    return {"message": "Sentinel API active. Frontend index.html not found."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
