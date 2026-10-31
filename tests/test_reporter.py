import pytest
from core.reporter import export_events_to_csv, export_alerts_to_csv, generate_executive_summary_report

def test_csv_exports():
    events = [
        {"timestamp": "2026-10-25 10:00:00", "username": "alice", "ip_address": "10.0.0.1", "login_result": "SUCCESS"},
        {"timestamp": "2026-10-25 10:05:00", "username": "bob", "ip_address": "10.0.0.2", "login_result": "FAILURE"}
    ]
    csv_str = export_events_to_csv(events)
    assert "timestamp,username,ip_address,login_result" in csv_str
    assert "alice" in csv_str
    assert "bob" in csv_str

    alerts = [
        {"alert_id": "ALT-001", "username": "charlie", "severity": "HIGH", "detection_rule": "RULE_BRUTE_FORCE_BURST", "status": "New"}
    ]
    alert_csv = export_alerts_to_csv(alerts)
    assert "ALT-001" in alert_csv
    assert "charlie" in alert_csv

def test_executive_summary_content():
    kpis = {
        "total_events": 150,
        "success_events": 130,
        "failed_events": 20,
        "suspicious_events": 5,
        "open_alerts": 4,
        "closed_alerts": 1
    }
    alerts = [
        {"username": "charlie", "severity": "HIGH", "status": "New"},
        {"username": "david", "severity": "CRITICAL", "status": "Investigating"}
    ]
    report = generate_executive_summary_report(kpis, alerts, generated_by="Auditor")
    assert "AI Company Guardian" in report
    assert "Total Ingested Events:** 150" in report
    assert "CRITICAL:** 1" in report
    assert "HIGH:** 1" in report
    assert "charlie" in report
    assert "suspected anomalies" in report
