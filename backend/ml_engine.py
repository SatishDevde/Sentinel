import numpy as np
from sklearn.ensemble import IsolationForest
import math
from typing import Dict, Any, List, Tuple

class MLAnomalyDetector:
    """
    Module 2: Machine Learning Anomaly Detection
    Learns normal baseline behavior from IoT log metrics and flags statistical anomalies.
    """

    def __init__(self):
        # Contamination estimated at ~5% abnormal patterns
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.is_fitted = False
        self._fit_default_baseline()

    def _extract_features(self, log: Dict[str, Any]) -> List[float]:
        """
        Extracts numerical feature vector from normalized log entry.
        Features:
        1. target_port normalized
        2. payload length
        3. log_level score (INFO=1, WARN=2, ERROR=3, CRITICAL=4)
        4. log_type score (system=1, network=2, auth=3)
        5. action string entropy
        6. payload string entropy
        """
        target_port = float(log.get("target_port") or 80) / 65535.0
        payload = str(log.get("payload") or "")
        raw = str(log.get("raw_message") or "")
        payload_len = len(payload) / 1000.0  # normalize
        
        level_map = {"INFO": 1.0, "WARNING": 2.0, "WARN": 2.0, "ERROR": 3.0, "CRITICAL": 4.0}
        log_level_score = level_map.get(log.get("log_level", "INFO").upper(), 1.0)
        
        type_map = {"system": 1.0, "network": 2.0, "authentication": 3.0}
        log_type_score = type_map.get(log.get("log_type", "system").lower(), 1.0)
        
        action_entropy = self._shannon_entropy(str(log.get("action", "")))
        payload_entropy = self._shannon_entropy(payload)
        
        return [target_port, payload_len, log_level_score, log_type_score, action_entropy, payload_entropy]

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return - sum([p * math.log2(p) for p in prob])

    def _fit_default_baseline(self):
        """Generates synthetic baseline of normal IoT logs and fits the model."""
        normal_logs = []
        # Generate 200 normal samples
        for i in range(200):
            normal_logs.append({
                "target_port": np.random.choice([80, 443, 8080, 1883, 5683]),
                "payload": f"Normal telemetry payload sensor status ok id={i}",
                "raw_message": "INFO status report ok",
                "log_level": "INFO",
                "log_type": np.random.choice(["system", "network", "authentication"]),
                "action": np.random.choice(["HEARTBEAT", "SENSOR_READ", "DATA_SYNC", "STATUS_OK"])
            })
            
        X = [self._extract_features(l) for l in normal_logs]
        self.model.fit(X)
        self.is_fitted = True

    def predict_anomaly(self, log: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Returns (is_anomaly: bool, anomaly_score: float [0.0 to 1.0])
        Higher score indicates stronger anomaly (anomaly_score > 0.50).
        """
        features = [self._extract_features(log)]
        
        # decision_function gives positive scores for inliers (~+0.1 to +0.25) 
        # and negative scores for outliers (~-0.1 to -0.3)
        raw_df = float(self.model.decision_function(features)[0])
        anomaly_score = max(0.0, min(1.0, 0.5 - (raw_df * 3.0)))
        
        is_anomaly = bool(anomaly_score > 0.50)
        return is_anomaly, round(anomaly_score, 4)





    def train_on_logs(self, logs: List[Dict[str, Any]]):
        """Retrains the ML model on custom log batch."""
        if len(logs) < 10:
            return
        X = [self._extract_features(l) for l in logs]
        self.model.fit(X)
        self.is_fitted = True
