import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def generate_alert_id() -> str:
    """Generate a clean, professional alert reference code."""
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"ALT-{date_part}-{unique_suffix}"

def evaluate_detection_rules(
    events: List[Dict[str, Any]],
    saved_event_ids: Dict[str, int],  # mapping event_hash -> database event_id
    brute_force_thresh: int = 5,
    brute_force_window_min: int = 10,
    ip_spray_thresh: int = 10,
    ip_spray_window_min: int = 15
) -> List[Dict[str, Any]]:
    """
    Evaluates rule-based detections across a batch of security events.
    Events are sorted chronologically.
    """
    if not events:
        return []

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    generated_alerts: List[Dict[str, Any]] = []
    seen_event_rules = set() # Avoid generating identical rule alerts for the same event

    # Group events by user and by IP
    user_events: Dict[str, List[Dict[str, Any]]] = {}
    ip_events: Dict[str, List[Dict[str, Any]]] = {}

    for ev in sorted_events:
        user_events.setdefault(ev["username"], []).append(ev)
        ip_events.setdefault(ev["ip_address"], []).append(ev)

    # 1. EVALUATE BRUTE-FORCE BURST & SUCCESS-AFTER-BURST (User-centric)
    for username, u_evts in user_events.items():
        window_delta = timedelta(minutes=brute_force_window_min)
        n = len(u_evts)

        for i in range(n):
            current_ev = u_evts[i]
            current_time = datetime.strptime(current_ev["timestamp"], "%Y-%m-%d %H:%M:%S")

            # Look backwards in time within the window
            window_start = current_time - window_delta
            window_slice = [
                e for e in u_evts[:i + 1]
                if datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S") >= window_start
            ]

            failed_in_window = [e for e in window_slice if e["login_result"] == "FAILURE"]

            # Scenario A: Brute-Force Burst (>= threshold failures)
            if len(failed_in_window) >= brute_force_thresh:
                ev_id = saved_event_ids.get(current_ev["event_hash"])
                if ev_id:
                    dedup_key = (ev_id, "RULE_BRUTE_FORCE_BURST")
                    if dedup_key not in seen_event_rules:
                        seen_event_rules.add(dedup_key)
                        
                        # Scenario B: High-risk compromise if this current event succeeded after the failures
                        if current_ev["login_result"] == "SUCCESS":
                            generated_alerts.append({
                                "alert_id": generate_alert_id(),
                                "event_id": ev_id,
                                "username": username,
                                "detection_rule": "RULE_BRUTE_FORCE_SUCCESS_COMPROMISE",
                                "detection_method": "RULE",
                                "severity": "CRITICAL",
                                "reason": f"CRITICAL: User '{username}' achieved SUCCESSFUL login immediately after {len(failed_in_window)} failed attempts within {brute_force_window_min} minutes from IP {current_ev['ip_address']}."
                            })
                        else:
                            generated_alerts.append({
                                "alert_id": generate_alert_id(),
                                "event_id": ev_id,
                                "username": username,
                                "detection_rule": "RULE_BRUTE_FORCE_BURST",
                                "detection_method": "RULE",
                                "severity": "HIGH",
                                "reason": f"HIGH: Detected repeated failed login attempts ({len(failed_in_window)} failures) for user '{username}' within {brute_force_window_min} minutes from IP {current_ev['ip_address']}."
                            })

    # 2. EVALUATE DISTRIBUTED IP SPRAYING (IP-centric)
    for ip_addr, ip_evts in ip_events.items():
        spray_delta = timedelta(minutes=ip_spray_window_min)
        n = len(ip_evts)

        for i in range(n):
            current_ev = ip_evts[i]
            current_time = datetime.strptime(current_ev["timestamp"], "%Y-%m-%d %H:%M:%S")
            window_start = current_time - spray_delta

            window_slice = [
                e for e in ip_evts[:i + 1]
                if datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S") >= window_start
            ]
            failed_in_window = [e for e in window_slice if e["login_result"] == "FAILURE"]
            unique_targets = set(e["username"] for e in failed_in_window)

            if len(unique_targets) >= 3 and len(failed_in_window) >= ip_spray_thresh:
                ev_id = saved_event_ids.get(current_ev["event_hash"])
                if ev_id:
                    dedup_key = (ev_id, "RULE_PASSWORD_SPRAY")
                    if dedup_key not in seen_event_rules:
                        seen_event_rules.add(dedup_key)
                        generated_alerts.append({
                            "alert_id": generate_alert_id(),
                            "event_id": ev_id,
                            "username": current_ev["username"],
                            "detection_rule": "RULE_PASSWORD_SPRAY",
                            "detection_method": "RULE",
                            "severity": "HIGH",
                            "reason": f"HIGH: IP {ip_addr} initiated password spray attacks targeting {len(unique_targets)} distinct usernames with {len(failed_in_window)} total failures within {ip_spray_window_min} minutes."
                        })

    # 3. EVALUATE OFF-HOURS ACCESS (Event-centric)
    for ev in sorted_events:
        if ev.get("is_off_hours"):
            ev_id = saved_event_ids.get(ev["event_hash"])
            if ev_id:
                dedup_key = (ev_id, "RULE_OFF_HOURS_ACCESS")
                if dedup_key not in seen_event_rules:
                    seen_event_rules.add(dedup_key)
                    # Off hours failure vs success
                    sev = "MEDIUM" if ev["login_result"] == "SUCCESS" else "LOW"
                    generated_alerts.append({
                        "alert_id": generate_alert_id(),
                        "event_id": ev_id,
                        "username": ev["username"],
                        "detection_rule": "RULE_OFF_HOURS_ACCESS",
                        "detection_method": "RULE",
                        "severity": sev,
                        "reason": f"{sev}: Authentication event for user '{ev['username']}' occurred outside designated working hours at hour {ev['hour_of_day']}:00 (day {ev['day_of_week']}) from IP {ev['ip_address']} with result {ev['login_result']}."
                    })

    return generated_alerts
