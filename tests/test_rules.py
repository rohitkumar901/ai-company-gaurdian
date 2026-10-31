import pytest
from core.rules import evaluate_detection_rules

def test_normal_activity_no_brute_force():
    events = [
        {"timestamp": "2026-10-25 09:00:00", "username": "alice", "ip_address": "10.0.0.1", "login_result": "SUCCESS", "event_hash": "h1", "is_off_hours": False},
        {"timestamp": "2026-10-25 11:30:00", "username": "alice", "ip_address": "10.0.0.1", "login_result": "SUCCESS", "event_hash": "h2", "is_off_hours": False},
        {"timestamp": "2026-10-25 14:15:00", "username": "bob", "ip_address": "10.0.0.2", "login_result": "SUCCESS", "event_hash": "h3", "is_off_hours": False}
    ]
    hash_to_id = {"h1": 1, "h2": 2, "h3": 3}
    alerts = evaluate_detection_rules(events, hash_to_id, brute_force_thresh=5, brute_force_window_min=10)
    assert len(alerts) == 0

def test_brute_force_burst_detection():
    events = []
    hash_to_id = {}
    # 5 failures in 2 minutes for charlie
    for i in range(5):
        h = f"h_bf_{i}"
        events.append({
            "timestamp": f"2026-10-25 10:0{i}:00",
            "username": "charlie",
            "ip_address": "198.51.100.42",
            "login_result": "FAILURE",
            "event_hash": h,
            "is_off_hours": False
        })
        hash_to_id[h] = i + 1

    alerts = evaluate_detection_rules(events, hash_to_id, brute_force_thresh=5, brute_force_window_min=10)
    bf_alerts = [a for a in alerts if a["detection_rule"] == "RULE_BRUTE_FORCE_BURST"]
    assert len(bf_alerts) >= 1
    assert bf_alerts[0]["severity"] == "HIGH"
    assert bf_alerts[0]["username"] == "charlie"

def test_compromise_after_burst_detection():
    events = []
    hash_to_id = {}
    for i in range(5):
        h = f"h_bf_{i}"
        events.append({
            "timestamp": f"2026-10-25 10:0{i}:00",
            "username": "david",
            "ip_address": "203.0.113.88",
            "login_result": "FAILURE",
            "event_hash": h,
            "is_off_hours": False
        })
        hash_to_id[h] = i + 1

    # 6th event is SUCCESS from attacker
    h_succ = "h_succ"
    events.append({
        "timestamp": "2026-10-25 10:05:30",
        "username": "david",
        "ip_address": "203.0.113.88",
        "login_result": "SUCCESS",
        "event_hash": h_succ,
        "is_off_hours": False
    })
    hash_to_id[h_succ] = 6

    alerts = evaluate_detection_rules(events, hash_to_id, brute_force_thresh=5, brute_force_window_min=10)
    comp_alerts = [a for a in alerts if a["detection_rule"] == "RULE_BRUTE_FORCE_SUCCESS_COMPROMISE"]
    assert len(comp_alerts) >= 1
    assert comp_alerts[0]["severity"] == "CRITICAL"

def test_password_spray_detection():
    events = []
    hash_to_id = {}
    users = ["user1", "user2", "user3", "user4", "user5"]
    spray_ip = "185.220.101.5"

    count = 1
    for u in users:
        for attempt in range(2):
            h = f"h_spray_{count}"
            events.append({
                "timestamp": f"2026-10-25 12:0{count % 10}:00",
                "username": u,
                "ip_address": spray_ip,
                "login_result": "FAILURE",
                "event_hash": h,
                "is_off_hours": False
            })
            hash_to_id[h] = count
            count += 1

    alerts = evaluate_detection_rules(events, hash_to_id, ip_spray_thresh=10, ip_spray_window_min=15)
    spray_alerts = [a for a in alerts if a["detection_rule"] == "RULE_PASSWORD_SPRAY"]
    assert len(spray_alerts) >= 1
    assert spray_alerts[0]["severity"] == "HIGH"
