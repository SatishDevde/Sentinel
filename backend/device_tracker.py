from typing import List, Dict, Any, Optional
from backend.database import get_db_connection
from datetime import datetime

class DeviceTracker:
    """
    Module 3: Device and Activity Tracking
    Tracks connected IoT devices, links detected threat events to affected devices,
    updates risk metrics, and provides historical activity timelines.
    """

    @staticmethod
    def get_all_devices() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM iot_devices ORDER BY risk_score DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_device_by_id(device_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM iot_devices WHERE device_id = ?", (device_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def register_or_update_device(device_id: str, device_type: str = "Generic IoT Device", ip_address: str = "192.168.1.100"):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("SELECT * FROM iot_devices WHERE device_id = ?", (device_id,))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE iot_devices 
                SET last_seen = ?, ip_address = COALESCE(?, ip_address)
                WHERE device_id = ?
            ''', (now, ip_address, device_id))
        else:
            name = f"{device_type} ({device_id})"
            cursor.execute('''
                INSERT INTO iot_devices (device_id, name, device_type, ip_address, location, status, risk_score, last_seen, total_threats, firmware_version)
                VALUES (?, ?, ?, ?, 'Building A', 'ONLINE', 0, ?, 0, 'v1.0.0')
            ''', (device_id, name, device_type, ip_address, now))
            
        conn.commit()
        conn.close()

    @staticmethod
    def record_threat_impact(device_id: str, severity: str):
        """
        Increments threat count and updates risk score/status for affected device.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        severity_points = {
            "Critical": 35,
            "High": 20,
            "Medium": 10,
            "Low": 5
        }
        pts = severity_points.get(severity, 10)

        cursor.execute("SELECT risk_score, total_threats FROM iot_devices WHERE device_id = ?", (device_id,))
        row = cursor.fetchone()
        
        if row:
            new_score = min(100, (row["risk_score"] or 0) + pts)
            new_threats = (row["total_threats"] or 0) + 1
            
            status = "ONLINE"
            if new_score >= 70:
                status = "CRITICAL"
            elif new_score >= 40:
                status = "WARNING"
                
            cursor.execute('''
                UPDATE iot_devices 
                SET risk_score = ?, total_threats = ?, status = ?, last_seen = ?
                WHERE device_id = ?
            ''', (new_score, new_threats, status, datetime.now().isoformat(), device_id))
            conn.commit()
            
        conn.close()

    @staticmethod
    def get_device_activity_timeline(device_id: str) -> List[Dict[str, Any]]:
        """Returns recent logs and threats associated with a specific device."""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM threat_events WHERE device_id = ? ORDER BY id DESC LIMIT 20", (device_id,))
        threats = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM iot_logs WHERE device_id = ? ORDER BY id DESC LIMIT 20", (device_id,))
        logs = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        return {"threats": threats, "logs": logs}
