import pytest
import pandas as pd
from core.ml_detector import SecurityAnomalyDetector, FEATURE_COLUMNS

def test_feature_extraction():
    detector = SecurityAnomalyDetector()
    events = [
        {"hour_of_day": 10, "day_of_week": 1, "is_off_hours": False, "login_result": "SUCCESS", "username": "alice", "ip_address": "10.0.0.1"},
        {"hour_of_day": 23, "day_of_week": 5, "is_off_hours": True, "login_result": "FAILURE", "username": "bob", "ip_address": "198.51.100.1"}
    ]
    df = detector.extract_features(events)
    assert len(df) == 2
    for col in FEATURE_COLUMNS:
        assert col in df.columns

def test_ml_training_and_inference():
    detector = SecurityAnomalyDetector(contamination=0.1)

    # Synthetic normal and anomalous events
    events = []
    # 20 normal events
    for i in range(20):
        events.append({
            "hour_of_day": 10 + (i % 5),
            "day_of_week": 1,
            "is_off_hours": False,
            "login_result": "SUCCESS",
            "username": f"user_{i % 3}",
            "ip_address": "10.0.0.1",
            "event_hash": f"hash_norm_{i}"
        })
    # 2 anomalous events (off hours, failure, rare IP)
    for i in range(2):
        events.append({
            "hour_of_day": 3,
            "day_of_week": 6,
            "is_off_hours": True,
            "login_result": "FAILURE",
            "username": "victim",
            "ip_address": f"203.0.113.{i}",
            "event_hash": f"hash_anom_{i}"
        })

    train_info = detector.train(events)
    assert train_info["trained_samples"] == 22

    hash_to_id = {ev["event_hash"]: idx + 1 for idx, ev in enumerate(events)}
    alerts, feat_df = detector.predict_anomalies(events, hash_to_id, anomaly_threshold=0.60)

    assert "anomaly_score" in feat_df.columns
    assert len(feat_df) == 22
    # Anomaly scores should be between 0.0 and 1.0
    assert feat_df["anomaly_score"].min() >= 0.0
    assert feat_df["anomaly_score"].max() <= 1.0

def test_ground_truth_evaluation():
    detector = SecurityAnomalyDetector(contamination=0.1)

    events = []
    labels = []
    # 30 benign
    for i in range(30):
        events.append({
            "hour_of_day": 11,
            "day_of_week": 2,
            "is_off_hours": False,
            "login_result": "SUCCESS",
            "username": "alice",
            "ip_address": "10.0.0.1"
        })
        labels.append(0)

    # 5 attack
    for i in range(5):
        events.append({
            "hour_of_day": 2,
            "day_of_week": 6,
            "is_off_hours": True,
            "login_result": "FAILURE",
            "username": "alice",
            "ip_address": f"198.51.100.{i}"
        })
        labels.append(1)

    metrics = detector.evaluate_with_ground_truth(events, labels, anomaly_threshold=0.60)
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "false_positive_rate" in metrics
    assert metrics["total_tested"] == 35
