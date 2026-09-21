import pytest
from backend.ml_engine import MLAnomalyDetector

def test_ml_anomaly_detector_initialization():
    detector = MLAnomalyDetector()
    assert detector.is_fitted is True

def test_ml_normal_vs_abnormal():
    detector = MLAnomalyDetector()
    
    normal_log = {
        "target_port": 1883,
        "payload": "Normal operational telemetry status ok",
        "raw_message": "INFO status report ok",
        "log_level": "INFO",
        "log_type": "network",
        "action": "HEARTBEAT"
    }
    
    abnormal_log = {
        "target_port": 65432,
        "payload": "X"*5000 + "EXPLOIT_OVERFLOW_STRING_PATTERN",
        "raw_message": "CRITICAL EXPLOIT OVERFLOW",
        "log_level": "CRITICAL",
        "log_type": "authentication",
        "action": "OVERFLOW_BUFFER_MALFORMED"
    }
    
    _, normal_score = detector.predict_anomaly(normal_log)
    is_anomaly, abnormal_score = detector.predict_anomaly(abnormal_log)
    
    assert abnormal_score > normal_score
    assert is_anomaly is True
