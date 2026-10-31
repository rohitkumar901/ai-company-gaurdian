import io
import json
import pytest
from core.log_parser import parse_security_log_file, compute_event_hash, is_within_off_hours
from datetime import datetime

def test_compute_event_hash():
    h1 = compute_event_hash("2026-10-25 10:00:00", "alice", "192.168.1.1", "SUCCESS")
    h2 = compute_event_hash("2026-10-25 10:00:00", "ALICE", "192.168.1.1", "success")
    h3 = compute_event_hash("2026-10-25 10:00:01", "alice", "192.168.1.1", "SUCCESS")
    assert h1 == h2 # Case normalized
    assert h1 != h3

def test_is_within_off_hours():
    # Wednesday 10 AM (Weekday business hours) -> False
    wed_10am = datetime(2026, 10, 28, 10, 0, 0)
    assert is_within_off_hours(wed_10am, 8, 20) is False

    # Wednesday 11 PM (Weekday night) -> True
    wed_11pm = datetime(2026, 10, 28, 23, 0, 0)
    assert is_within_off_hours(wed_11pm, 8, 20) is True

    # Sunday 2 PM (Weekend) -> True
    sun_2pm = datetime(2026, 11, 1, 14, 0, 0)
    assert is_within_off_hours(sun_2pm, 8, 20) is True

def test_parse_valid_csv():
    csv_content = """timestamp,username,ip_address,login_result,event_type
2026-10-25 09:30:00,bob_hr,10.0.1.22,SUCCESS,LOGIN
2026-10-25 09:35:00,bob_hr,10.0.1.22,FAILURE,LOGIN
"""
    file_buf = io.BytesIO(csv_content.encode('utf-8'))
    valid, invalid, summary = parse_security_log_file(file_buf, "test.csv")

    assert summary["total_rows"] == 2
    assert len(valid) == 2
    assert len(invalid) == 0
    assert valid[0]["username"] == "bob_hr"
    assert valid[0]["login_result"] == "SUCCESS"
    assert valid[1]["login_result"] == "FAILURE"

def test_parse_valid_json():
    json_data = [
        {"timestamp": "2026-10-25 14:00:00", "username": "alice_dev", "ip_address": "10.0.1.15", "login_result": "SUCCESS"},
        {"timestamp": "2026-10-25 14:05:00", "username": "alice_dev", "ip_address": "10.0.1.15", "login_result": "FAILURE"}
    ]
    json_bytes = json.dumps(json_data).encode('utf-8')
    valid, invalid, summary = parse_security_log_file(json_bytes, "test.json")
    assert len(valid) == 2
    assert summary["invalid_rows"] == 0

def test_parse_missing_required_columns():
    csv_bad = """user,result
alice,SUCCESS
"""
    file_buf = io.BytesIO(csv_bad.encode('utf-8'))
    with pytest.raises(ValueError, match="Missing mandatory columns"):
        parse_security_log_file(file_buf, "bad.csv")

def test_parse_invalid_records_quarantine():
    csv_with_errors = """timestamp,username,ip_address,login_result
2026-10-25 09:00:00,good_user,10.0.0.1,SUCCESS
not_a_valid_date,bad_date_user,10.0.0.2,SUCCESS
2026-10-25 09:10:00,,10.0.0.3,SUCCESS
2026-10-25 09:15:00,bad_result_user,10.0.0.4,UNKNOWN_RESULT
"""
    file_buf = io.BytesIO(csv_with_errors.encode('utf-8'))
    valid, invalid, summary = parse_security_log_file(file_buf, "errors.csv")
    assert summary["total_rows"] == 4
    assert len(valid) == 1
    assert len(invalid) == 3
    assert valid[0]["username"] == "good_user"
