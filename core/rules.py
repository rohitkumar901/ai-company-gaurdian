import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from config import SUSPICIOUS_USER_AGENTS

def generate_alert_id() -> str:
    """Generate enterprise-standard incident reference ID."""
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"ALT-{date_part}-{unique_suffix}"

def evaluate_detection_rules(
    events: List[Dict[str, Any]],
    saved_event_ids: Dict[str, int],
    brute_force_thresh: int = 5,
    brute_force_window_min: int = 10,
    ip_spray_thresh: int = 10,
    ip_spray_window_min: int = 15,
    active_blocked_ips: Optional[set] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates enterprise threat detection rules across security events,
    tagging each alert with official MITRE ATT&CK Tactics & Techniques.
    """
    if not events:
        return []

    blocked_ip_set = active_blocked_ips or set()
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    generated_alerts: List[Dict[str, Any]] = []
    seen_event_rules = set()

    user_events: Dict[str, List[Dict[str, Any]]] = {}
    ip_events: Dict[str, List[Dict[str, Any]]] = {}

    for ev in sorted_events:
        user_events.setdefault(ev["username"], []).append(ev)
        ip_events.setdefault(ev["ip_address"], []).append(ev)

    # 1. EVALUATE BRUTE-FORCE BURST & COMPROMISE (MITRE T1110.001 & T1078.003)
    for username, u_evts in user_events.items():
        window_delta = timedelta(minutes=brute_force_window_min)
        n = len(u_evts)

        for i in range(n):
            current_ev = u_evts[i]
            current_time = datetime.strptime(current_ev["timestamp"], "%Y-%m-%d %H:%M:%S")

            window_start = current_time - window_delta
            window_slice = [
                e for e in u_evts[:i + 1]
                if datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S") >= window_start
            ]
            failed_in_window = [e for e in window_slice if e["login_result"] == "FAILURE"]

            if len(failed_in_window) >= brute_force_thresh:
                ev_id = saved_event_ids.get(current_ev["event_hash"])
                if ev_id:
                    dedup_key = (ev_id, "RULE_BRUTE_FORCE_BURST")
                    if dedup_key not in seen_event_rules:
                        seen_event_rules.add(dedup_key)
                        
                        # Scenario A: Account Compromise (Immediate Success after failure burst)
                        if current_ev["login_result"] == "SUCCESS":
                            generated_alerts.append({
                                "alert_id": generate_alert_id(),
                                "event_id": ev_id,
                                "username": username,
                                "detection_rule": "RULE_BRUTE_FORCE_SUCCESS_COMPROMISE",
                                "detection_method": "RULE",
                                "severity": "CRITICAL",
                                "mitre_technique_id": "T1078.003",
                                "mitre_technique_name": "Valid Accounts: Local Accounts",
                                "mitre_tactic": "Initial Access / Persistence",
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
                                "mitre_technique_id": "T1110.001",
                                "mitre_technique_name": "Brute Force: Password Guessing",
                                "mitre_tactic": "Credential Access",
                                "reason": f"HIGH: Detected repeated failed login attempts ({len(failed_in_window)} failures) for user '{username}' within {brute_force_window_min} minutes from IP {current_ev['ip_address']}."
                            })

    # 2. EVALUATE PASSWORD SPRAY (MITRE T1110.003)
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
                            "mitre_technique_id": "T1110.003",
                            "mitre_technique_name": "Brute Force: Password Spraying",
                            "mitre_tactic": "Credential Access",
                            "reason": f"HIGH: IP {ip_addr} launched distributed password spraying targeting {len(unique_targets)} accounts with {len(failed_in_window)} failures within {ip_spray_window_min} minutes."
                        })

    # 3. EVALUATE SUSPICIOUS TOOL USER AGENTS (MITRE T1071.001)
    for ev in sorted_events:
        dev_info_lower = str(ev.get("device_info", "")).lower()
        for tool_ua in SUSPICIOUS_USER_AGENTS:
            if tool_ua in dev_info_lower:
                ev_id = saved_event_ids.get(ev["event_hash"])
                if ev_id:
                    dedup_key = (ev_id, f"RULE_SUSPICIOUS_UA_{tool_ua}")
                    if dedup_key not in seen_event_rules:
                        seen_event_rules.add(dedup_key)
                        generated_alerts.append({
                            "alert_id": generate_alert_id(),
                            "event_id": ev_id,
                            "username": ev["username"],
                            "detection_rule": f"RULE_ATTACK_TOOL_USER_AGENT",
                            "detection_method": "RULE",
                            "severity": "HIGH",
                            "mitre_technique_id": "T1071.001",
                            "mitre_technique_name": "Application Layer Protocol: Web Protocols",
                            "mitre_tactic": "Command and Control / Recon",
                            "reason": f"HIGH: Authentication request originated from known penetration/brute-force tool user-agent '{tool_ua.capitalize()}' ({ev['device_info']}) from IP {ev['ip_address']}."
                        })
                break

    # 4. EVALUATE CONTAINED / BLOCKED IP ACTIVE ATTEMPTS (MITRE T1090)
    for ev in sorted_events:
        if ev["ip_address"] in blocked_ip_set:
            ev_id = saved_event_ids.get(ev["event_hash"])
            if ev_id:
                dedup_key = (ev_id, "RULE_BLOCKED_IP_VIOLATION")
                if dedup_key not in seen_event_rules:
                    seen_event_rules.add(dedup_key)
                    generated_alerts.append({
                        "alert_id": generate_alert_id(),
                        "event_id": ev_id,
                        "username": ev["username"],
                        "detection_rule": "RULE_BLOCKED_IP_VIOLATION",
                        "detection_method": "RULE",
                        "severity": "CRITICAL",
                        "mitre_technique_id": "T1090",
                        "mitre_technique_name": "Proxy / Blacklisted Source Attempt",
                        "mitre_tactic": "Defense Evasion",
                        "reason": f"CRITICAL: Login attempt blocked for user '{ev['username']}' from firewall-blacklisted IP {ev['ip_address']}."
                    })

    # 5. EVALUATE OFF-HOURS ACCESS (MITRE T1078.002)
    for ev in sorted_events:
        if ev.get("is_off_hours"):
            ev_id = saved_event_ids.get(ev["event_hash"])
            if ev_id:
                dedup_key = (ev_id, "RULE_OFF_HOURS_ACCESS")
                if dedup_key not in seen_event_rules:
                    seen_event_rules.add(dedup_key)
                    sev = "MEDIUM" if ev["login_result"] == "SUCCESS" else "LOW"
                    generated_alerts.append({
                        "alert_id": generate_alert_id(),
                        "event_id": ev_id,
                        "username": ev["username"],
                        "detection_rule": "RULE_OFF_HOURS_ACCESS",
                        "detection_method": "RULE",
                        "severity": sev,
                        "mitre_technique_id": "T1078.002",
                        "mitre_technique_name": "Valid Accounts: Domain Accounts",
                        "mitre_tactic": "Defense Evasion / Initial Access",
                        "reason": f"{sev}: Out-of-hours login for '{ev['username']}' at {ev['hour_of_day']}:00 (day {ev['day_of_week']}) from IP {ev['ip_address']} ({ev['country_code']}) with result {ev['login_result']}."
                    })

    return generated_alerts
