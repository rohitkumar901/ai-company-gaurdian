import os
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from config import MODEL_PATH
from core.rules import generate_alert_id

FEATURE_COLUMNS = [
    "hour_of_day",
    "day_of_week",
    "is_off_hours",
    "is_success",
    "user_fail_count",
    "ip_occurrences"
]

class SecurityAnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.version = "IsolationForest-Enterprise-v2.5"

    def extract_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Engineer tabular numerical telemetry features from raw security event dicts."""
        df = pd.DataFrame(events)
        if df.empty:
            return pd.DataFrame(columns=FEATURE_COLUMNS)

        user_fails = df[df["login_result"] == "FAILURE"]["username"].value_counts().to_dict()
        ip_counts = df["ip_address"].value_counts().to_dict()

        features = []
        for _, row in df.iterrows():
            hour = int(row.get("hour_of_day", 12))
            dow = int(row.get("day_of_week", 1))
            off_hours = 1 if row.get("is_off_hours") else 0
            is_success = 1 if str(row.get("login_result")).upper() == "SUCCESS" else 0
            u_fail_cnt = user_fails.get(row.get("username"), 0)
            ip_cnt = ip_counts.get(row.get("ip_address"), 1)

            features.append({
                "hour_of_day": hour,
                "day_of_week": dow,
                "is_off_hours": off_hours,
                "is_success": is_success,
                "user_fail_count": u_fail_cnt,
                "ip_occurrences": ip_cnt
            })

        return pd.DataFrame(features)

    def train(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train Isolation Forest on event features and persist model."""
        feature_df = self.extract_features(events)
        if len(feature_df) < 5:
            raise ValueError("Insufficient events to train Isolation Forest. At least 5 events required.")

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        self.model.fit(feature_df[FEATURE_COLUMNS])

        # Persist model
        joblib.dump(self.model, MODEL_PATH)

        return {
            "model_version": self.version,
            "trained_samples": len(feature_df),
            "contamination": self.contamination,
            "features_used": FEATURE_COLUMNS
        }

    def load_model(self) -> bool:
        """Load persisted model if present."""
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                return True
            except Exception:
                return False
        return False

    def explain_anomaly(self, row_features: Dict[str, Any]) -> Dict[str, float]:
        """
        Explainable AI (XAI): Heuristic feature contribution attribution.
        Quantifies the percentage contribution of each feature towards the anomaly verdict.
        """
        weights = {}
        # Off-hours contribution
        weights["Off-Hours Timing"] = 35.0 if row_features.get("is_off_hours") == 1 else 5.0
        # Failure momentum
        fail_cnt = row_features.get("user_fail_count", 0)
        weights["User Failure Velocity"] = min(40.0, fail_cnt * 8.0)
        # IP rarity
        ip_cnt = row_features.get("ip_occurrences", 1)
        weights["IP Cluster Rarity"] = 25.0 if ip_cnt <= 2 else 5.0
        # Success vs Failure unexpectedness
        if row_features.get("is_success") == 0 and row_features.get("is_off_hours") == 1:
            weights["Out-of-Profile Failure"] = 20.0

        total_weight = sum(weights.values())
        if total_weight > 0:
            return {k: round((v / total_weight) * 100, 1) for k, v in weights.items()}
        return {"Baseline Deviation": 100.0}

    def predict_anomalies(
        self,
        events: List[Dict[str, Any]],
        saved_event_ids: Dict[str, int],
        anomaly_threshold: float = 0.65
    ) -> Tuple[List[Dict[str, Any]], pd.DataFrame]:
        """
        Inference across security events with normalized score [0, 1]
        and Explainable AI (XAI) feature attribution.
        """
        if not self.model and not self.load_model():
            self.train(events)

        feature_df = self.extract_features(events)
        if feature_df.empty or self.model is None:
            return [], pd.DataFrame()

        raw_scores = self.model.decision_function(feature_df[FEATURE_COLUMNS])
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s - min_s > 1e-6:
            norm_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
        else:
            norm_scores = np.full(len(raw_scores), 0.5)

        feature_df["anomaly_score"] = norm_scores
        feature_df["is_anomaly"] = norm_scores >= anomaly_threshold

        generated_alerts: List[Dict[str, Any]] = []

        for idx, ev in enumerate(events):
            score = float(norm_scores[idx])
            if score >= anomaly_threshold:
                ev_id = saved_event_ids.get(ev["event_hash"])
                if ev_id:
                    if score >= 0.85:
                        sev = "CRITICAL"
                    elif score >= 0.75:
                        sev = "HIGH"
                    else:
                        sev = "MEDIUM"

                    row_feat = feature_df.iloc[idx].to_dict()
                    explanations = self.explain_anomaly(row_feat)
                    top_driver = max(explanations.items(), key=lambda x: x[1])[0]

                    generated_alerts.append({
                        "alert_id": generate_alert_id(),
                        "event_id": ev_id,
                        "username": ev["username"],
                        "detection_rule": "ML_ISOLATION_FOREST_OUTLIER",
                        "detection_method": "ML",
                        "severity": sev,
                        "anomaly_score": round(score, 4),
                        "mitre_technique_id": "T1078.004",
                        "mitre_technique_name": "Valid Accounts: Cloud / Zero-Day Outlier",
                        "mitre_tactic": "Defense Evasion",
                        "reason": f"ML Anomaly Alert (Score: {round(score, 4)}). Primary Outlier Driver: {top_driver} ({explanations.get(top_driver)}% contribution). Event at hour={ev.get('hour_of_day')}, IP={ev.get('ip_address')}."
                    })

        return generated_alerts, feature_df

    def evaluate_with_ground_truth(
        self,
        events: List[Dict[str, Any]],
        ground_truth_labels: List[int],
        anomaly_threshold: float = 0.65
    ) -> Dict[str, Any]:
        """Benchmark ML detector accuracy against ground-truth security datasets."""
        if not self.model and not self.load_model():
            self.train(events)

        feature_df = self.extract_features(events)
        raw_scores = self.model.decision_function(feature_df[FEATURE_COLUMNS])
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s - min_s > 1e-6:
            norm_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
        else:
            norm_scores = np.full(len(raw_scores), 0.5)

        predictions = [1 if s >= anomaly_threshold else 0 for s in norm_scores]

        prec = precision_score(ground_truth_labels, predictions, zero_division=0)
        rec = recall_score(ground_truth_labels, predictions, zero_division=0)
        f1 = f1_score(ground_truth_labels, predictions, zero_division=0)
        cm = confusion_matrix(ground_truth_labels, predictions)

        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "total_tested": len(ground_truth_labels),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "false_positive_rate": round(float(fpr), 4),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
            "threshold_used": anomaly_threshold
        }
