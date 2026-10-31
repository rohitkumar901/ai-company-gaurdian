import pytest
from database.db import init_db, get_connection
from database.queries import (
    create_import_job,
    insert_security_events,
    get_security_events,
    create_alert,
    get_alerts,
    update_alert_status,
    add_investigation_note,
    get_investigation_notes,
    update_setting,
    get_all_settings,
    get_dashboard_kpis
)

@pytest.fixture
def test_db(tmp_path):
    path = str(tmp_path / "test_db.db")
    init_db(path)
    return path

def test_database_schema_and_integrity(test_db):
    conn = get_connection(test_db)
    cur = conn.cursor()
    # Verify all expected tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {r[0] for r in cur.fetchall()}
    expected = {"users", "import_jobs", "security_events", "alerts", "investigation_notes", "audit_history", "system_settings"}
    assert expected.issubset(tables)
    conn.close()

def test_events_and_alerts_lifecycle(test_db):
    job_id = create_import_job("test.csv", 10, 10, 0, 0, "tester", db_path=test_db)
    assert job_id > 0

    events = [
        {
            "timestamp": "2026-10-25 10:00:00",
            "username": "alice",
            "ip_address": "10.0.0.1",
            "login_result": "SUCCESS",
            "event_type": "LOGIN",
            "device_info": "Chrome",
            "country_code": "US",
            "hour_of_day": 10,
            "day_of_week": 6,
            "is_off_hours": False,
            "event_hash": "hash_alice_1"
        },
        {
            "timestamp": "2026-10-25 10:01:00",
            "username": "alice",
            "ip_address": "10.0.0.1",
            "login_result": "FAILURE",
            "event_type": "LOGIN",
            "device_info": "Chrome",
            "country_code": "US",
            "hour_of_day": 10,
            "day_of_week": 6,
            "is_off_hours": False,
            "event_hash": "hash_alice_2"
        }
    ]

    ins, dups = insert_security_events(events, job_id, db_path=test_db)
    assert ins == 2
    assert dups == 0

    # Test duplicate prevention via hash constraint
    ins_dup, dups2 = insert_security_events(events, job_id, db_path=test_db)
    assert ins_dup == 0
    assert dups2 == 2

    # Query events
    ev_list, total = get_security_events(db_path=test_db)
    assert total == 2
    assert len(ev_list) == 2

    # Create Alert
    alert_primary_id = create_alert(
        alert_id="ALT-TEST-001",
        event_id=ev_list[0]["id"],
        username="alice",
        detection_rule="RULE_TEST",
        detection_method="RULE",
        severity="HIGH",
        reason="Test alert trigger",
        db_path=test_db
    )
    assert alert_primary_id > 0

    # Update Alert Status
    updated = update_alert_status("ALT-TEST-001", "Investigating", db_path=test_db)
    assert updated is True

    # Add Note
    nid = add_investigation_note(alert_primary_id, "analyst", "Examining telemetry", db_path=test_db)
    assert nid > 0
    notes = get_investigation_notes(alert_primary_id, db_path=test_db)
    assert len(notes) == 1
    assert notes[0]["note"] == "Examining telemetry"

    # Dashboard KPIs
    kpis = get_dashboard_kpis(db_path=test_db)
    assert kpis["total_events"] == 2
    assert kpis["success_events"] == 1
    assert kpis["failed_events"] == 1
    assert kpis["open_alerts"] == 1
