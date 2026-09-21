import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = "/tmp/sentinel.db"
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")

def get_db_connection():
    # Automatically initialize DB if running on serverless ephemeral /tmp storage
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.close()
        init_db()
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table for normalized IoT logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id TEXT UNIQUE,
            timestamp TEXT,
            device_id TEXT,
            device_type TEXT,
            log_type TEXT, -- system, authentication, network
            log_level TEXT, -- INFO, WARNING, ERROR, CRITICAL
            source_ip TEXT,
            target_port INTEGER,
            action TEXT,
            payload TEXT,
            raw_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for detected security events/threats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            timestamp TEXT,
            device_id TEXT,
            device_name TEXT,
            device_type TEXT,
            threat_category TEXT, -- Brute Force, DoS, Port Scanning, Tampering, etc.
            severity TEXT, -- Critical, High, Medium, Low
            detection_method TEXT, -- Rule-Based, Machine Learning, Hybrid
            confidence_score REAL,
            anomaly_score REAL,
            matched_rule TEXT,
            source_ip TEXT,
            target_port INTEGER,
            evidence TEXT, -- JSON string detailing logs/metrics
            recommended_actions TEXT, -- JSON array of recommended human actions
            status TEXT DEFAULT 'ACTIVE', -- ACTIVE, ACKNOWLEDGED, RESOLVED
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for IoT device tracking & status
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_devices (
            device_id TEXT PRIMARY KEY,
            name TEXT,
            device_type TEXT, -- Industrial Sensor, Smart Camera, Smart Lock, Gateway
            ip_address TEXT,
            location TEXT,
            status TEXT DEFAULT 'ONLINE', -- ONLINE, WARNING, CRITICAL, OFFLINE
            risk_score INTEGER DEFAULT 0,
            last_seen TEXT,
            total_threats INTEGER DEFAULT 0,
            firmware_version TEXT
        )
    ''')
    
    # Table for Rule-Based Detection configuration
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            description TEXT,
            severity TEXT,
            enabled INTEGER DEFAULT 1,
            condition_json TEXT
        )
    ''')

    # Create indexes for high performance querying
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_device ON iot_logs(device_id);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON iot_logs(timestamp);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_device ON threat_events(device_id);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_events(severity);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threat_events(timestamp);')

    conn.commit()
    conn.close()
    
    seed_initial_devices()
    seed_initial_rules()

def seed_initial_devices():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    initial_devices = [
        ("DEV-CAM-01", "Front Gate Camera", "Smart Camera", "192.168.1.101", "Sector A - Main Entrance", "ONLINE", 15, datetime.now().isoformat(), 0, "v2.1.4"),
        ("DEV-LOCK-02", "Server Room Lock", "Smart Lock", "192.168.1.102", "Building B - Server Room", "ONLINE", 5, datetime.now().isoformat(), 0, "v1.8.0"),
        ("DEV-SENS-03", "Pressure Sensor #4", "Industrial Sensor", "192.168.1.103", "Factory Floor 1", "ONLINE", 0, datetime.now().isoformat(), 0, "v3.0.1"),
        ("DEV-GTW-04", "IoT Main Gateway", "IoT Gateway", "192.168.1.1", "Control Room", "ONLINE", 10, datetime.now().isoformat(), 0, "v4.2.0"),
        ("DEV-CAM-05", "Warehouse Camera", "Smart Camera", "192.168.1.105", "Warehouse Zone C", "ONLINE", 0, datetime.now().isoformat(), 0, "v2.1.4"),
        ("DEV-LOCK-06", "Lab Vault Lock", "Smart Lock", "192.168.1.106", "R&D Facility", "ONLINE", 0, datetime.now().isoformat(), 0, "v1.8.2")
    ]
    
    for dev in initial_devices:
        cursor.execute('''
            INSERT OR IGNORE INTO iot_devices 
            (device_id, name, device_type, ip_address, location, status, risk_score, last_seen, total_threats, firmware_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', dev)
        
    conn.commit()
    conn.close()

def seed_initial_rules():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    rules = [
        ("RULE-BF-01", "Repeated Failed Logins", "Brute Force Attack", 
         "Flags multiple failed authentication attempts from a single source within a short duration.", "High", 1, 
         json.dumps({"type": "failed_login_threshold", "count": 5, "window_seconds": 60})),
        
        ("RULE-PS-01", "Port Scan Reconnaissance", "Port Scanning", 
         "Detects rapid sequential connection attempts across multiple ports.", "Medium", 1, 
         json.dumps({"type": "port_probe_threshold", "unique_ports": 8, "window_seconds": 30})),
         
        ("RULE-DOS-01", "High Volume Traffic Flood", "DoS Attack", 
         "Detects request rate exceeding normal capacity indicating DoS/DDoS pattern.", "Critical", 1, 
         json.dumps({"type": "traffic_flood_threshold", "req_per_sec": 40, "window_seconds": 10})),
         
        ("RULE-TMP-01", "Unauthorized Configuration Change", "Configuration Tampering", 
         "Identifies modifications to device configuration files or system parameters without proper credentials.", "High", 1, 
         json.dumps({"type": "action_match", "target_actions": ["CONFIG_UPDATE", "SET_PARAM", "DISABLE_SECURITY"]})),
         
        ("RULE-FW-01", "Firmware Modification Attempt", "Firmware Tampering", 
         "Detects unauthorized firmware flash or unexpected binary signature replacement.", "Critical", 1, 
         json.dumps({"type": "action_match", "target_actions": ["FIRMWARE_FLASH", "OVERWRITE_BOOTLOADER"]})),
         
        ("RULE-SIP-01", "Suspicious External IP Communication", "Suspicious IP Communication", 
         "Flags communication with known untrusted or blacklisted IP ranges.", "High", 1, 
         json.dumps({"type": "untrusted_ip", "blacklisted_prefixes": ["198.51.100.", "203.0.113.", "45.33.32."]}))
    ]
    
    for r in rules:
        cursor.execute('''
            INSERT OR IGNORE INTO detection_rules 
            (rule_id, name, category, description, severity, enabled, condition_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', r)
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Sentinel Database Initialized Successfully!")
