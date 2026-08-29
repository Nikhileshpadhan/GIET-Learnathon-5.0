import time
import math
from collections import defaultdict, deque
from typing import Dict, Any, Tuple, List
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from config import ANOMALY_CONTAMINATION, SLIDING_WINDOW_SECONDS, MIN_SAMPLES_FOR_SCORING

class UnsupervisedAnomalyDetector:
    """
    Real-time Unsupervised Anomaly Detection using scikit-learn's IsolationForest.
    Scores behavioral anomalies (high request frequency, abnormal error spikes,
    endpoint scanning, payload size bursts) over a sliding time window.
    """

    def __init__(self):
        self.ip_history = defaultdict(lambda: deque(maxlen=200))
        self.feature_buffer = deque(maxlen=500)
        self.model = None
        self._init_model()

    def _init_model(self):
        if SKLEARN_AVAILABLE:
            try:
                self.model = IsolationForest(
                    n_estimators=50,
                    contamination=ANOMALY_CONTAMINATION,
                    random_state=42,
                    n_jobs=1
                )
            except Exception as e:
                print(f"[AnomalyDetector] IsolationForest init failed: {e}")
                self.model = None

    def record_event(self, event: Dict[str, Any]):
        """Records an HTTP event into the sliding window for behavioral tracking."""
        ip = event.get("ip", "127.0.0.1")
        now = time.time()

        entry = {
            "time": now,
            "path": event.get("path", "/"),
            "status": int(event.get("status", 200)),
            "duration_ms": float(event.get("duration_ms", 10.0)),
            "payload_len": len(str(event.get("payload", "")))
        }

        self.ip_history[ip].append(entry)

    def extract_features(self, ip: str) -> List[float]:
        """
        Extracts numerical behavioral feature vector for an IP:
        [request_count, error_rate, unique_paths, avg_payload_len, avg_duration_ms]
        """
        now = time.time()
        events = [e for e in self.ip_history[ip] if now - e["time"] <= SLIDING_WINDOW_SECONDS]

        if not events:
            return [0.0, 0.0, 0.0, 0.0, 0.0]

        count = float(len(events))
        errors = sum(1 for e in events if e["status"] >= 400)
        error_rate = errors / count if count > 0 else 0.0
        unique_paths = float(len(set(e["path"] for e in events)))
        avg_payload = sum(e["payload_len"] for e in events) / count
        avg_duration = sum(e["duration_ms"] for e in events) / count

        return [count, error_rate, unique_paths, avg_payload, avg_duration]

    def score_ip(self, ip: str) -> Tuple[bool, float, str]:
        """
        Returns (is_anomaly, anomaly_score, reason).
        Score is between 0.0 (normal) and 1.0 (highly anomalous).
        """
        features = self.extract_features(ip)
        req_count, error_rate, unique_paths, avg_payload, _ = features

        # Heuristic anomaly triggers (instant baseline protection)
        if req_count > 40:
            return True, 0.9, f"High request rate: {int(req_count)} req/min"
        if req_count > 10 and error_rate > 0.6:
            return True, 0.85, f"High error rate: {error_rate*100:.1f}% ({int(req_count)} reqs)"
        if req_count > 15 and unique_paths > 10:
            return True, 0.8, f"Endpoint scanning: {int(unique_paths)} unique paths"

        # IsolationForest scoring if sufficient history
        if SKLEARN_AVAILABLE and self.model is not None:
            self.feature_buffer.append(features)
            if len(self.feature_buffer) >= MIN_SAMPLES_FOR_SCORING:
                try:
                    X = np.array(list(self.feature_buffer))
                    # Fit on ongoing baseline stream
                    self.model.fit(X)
                    pred = self.model.predict([features])[0]  # -1 = anomaly, 1 = normal
                    score = float(-self.model.score_samples([features])[0])

                    if pred == -1 and score > 0.65:
                        return True, min(score, 1.0), f"IsolationForest anomaly score: {score:.2f}"
                except Exception:
                    pass

        return False, 0.0, "normal"
