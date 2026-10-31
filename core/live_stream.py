import time
import random
from datetime import datetime, timezone
from typing import Dict, Any, List
from core.log_parser import compute_event_hash, is_within_off_hours
from database.queries import insert_security_events, create_alert, get_connection
from core.rules import evaluate_detection_rules
from core.ml_detector import SecurityAnomalyDetector

SAMPLE_USERS = ["alice_dev", "bob_hr", "charlie_sales", "david_ops", "eve_qa", "grace_fin", "victor_eng"]
BENIGN_IPS = ["10.0.1.50", "10.0.1.72", "192.168.1.120", "192.168.1.135"]
ATTACK_IPS = ["198.51.100.99", "203.0.113.77", "185.220.101.44"]

def generate_live_event() -> Dict[str, Any]:
    """Generate a realistic live authentication telemetry packet."""
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    # 85% chance of normal event, 15% chance of attack telemetry
    is_malicious = random.random() < 0.15

    if is_malicious:
        scenario = random.choice(["brute_force", "off_hours", "spray", "compromise"])
        if scenario == "brute_force":
            u = random.choice(SAMPLE_USERS)
            ip = random.choice(ATTACK_IPS)
            res = "FAILURE"
            ua = "Hydra/9.5"
            cc = "RU"
        elif scenario == "spray":
            u = random.choice(SAMPLE_USERS)
            ip = "185.220.101.44"
            res = "FAILURE"
            ua = "Go-http-client/1.1"
            cc = "DE"
        elif scenario == "compromise":
            u = "david_ops"
            ip = "203.0.113.77"
            res = "SUCCESS" # Compromise success
            ua = "Python-requests/2.31.0"
            cc = "CN"
        else: # off_hours
            u = random.choice(SAMPLE_USERS)
            ip = "45.33.32.156"
            res = "FAILURE"
            ua = "TorBrowser/13.5"
            cc = "NL"
    else:
        u = random.choice(SAMPLE_USERS)
        ip = random.choice(BENIGN_IPS)
        res = "SUCCESS" if random.random() < 0.96 else "FAILURE"
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0"
        cc = "US"

    ev_hash = compute_event_hash(now_str, u, ip, res)
    off_hours = is_within_off_hours(now_dt)

    return {
        "timestamp": now_str,
        "username": u,
        "ip_address": ip,
        "login_result": res,
        "event_type": "LOGIN",
        "device_info": ua,
        "country_code": cc,
        "hour_of_day": now_dt.hour,
        "day_of_week": now_dt.weekday(),
        "is_off_hours": off_hours,
        "event_hash": ev_hash
    }

def ingest_live_batch(batch_size: int = 5) -> Dict[str, Any]:
    """Ingests a real-time live batch and triggers detection pipelines."""
    events = [generate_live_event() for _ in range(batch_size)]
    
    # Insert events into DB under job_id 1 or default
    ins, dups = insert_security_events(events, import_job_id=1)

    # Get IDs
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, event_hash FROM security_events ORDER BY id DESC LIMIT ?", (batch_size,))
    hash_map = {r["event_hash"]: r["id"] for r in cur.fetchall()}
    
    # Active blocked IPs
    cur.execute("SELECT ip_address FROM blocked_ips")
    blocked_ips = {r["ip_address"] for r in cur.fetchall()}
    conn.close()

    # Rule evaluation
    rule_alerts = evaluate_detection_rules(events, hash_map, active_blocked_ips=blocked_ips)
    alerts_created = 0
    for a in rule_alerts:
        create_alert(
            alert_id=a["alert_id"],
            event_id=a["event_id"],
            username=a["username"],
            detection_rule=a["detection_rule"],
            detection_method=a["detection_method"],
            severity=a["severity"],
            reason=a["reason"],
            mitre_technique_id=a.get("mitre_technique_id", "T1110"),
            mitre_technique_name=a.get("mitre_technique_name", "Brute Force"),
            mitre_tactic=a.get("mitre_tactic", "Credential Access")
        )
        alerts_created += 1

    return {
        "ingested_count": ins,
        "duplicates_count": dups,
        "alerts_generated": alerts_created,
        "latest_event": events[-1] if events else None
    }
