import sqlite3
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from database.db import get_connection, hash_password

# ----------------- USERS & AUTH QUERIES -----------------

def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def list_all_users(db_path: Optional[str] = None) -> List[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def create_user(username: str, plain_password: str, role: str, db_path: Optional[str] = None) -> bool:
    conn = get_connection(db_path)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.strip(), hash_password(plain_password), role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_user_password(username: str, new_password: str, db_path: Optional[str] = None) -> bool:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_password(new_password), username))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def delete_user(username: str, db_path: Optional[str] = None) -> bool:
    if username == "admin":
        return False # Protect primary admin
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted

# ----------------- IMPORT JOBS & EVENTS QUERIES -----------------

def create_import_job(filename: str, total_rows: int, valid_rows: int, invalid_rows: int, duplicate_rows: int, uploaded_by: str, db_path: Optional[str] = None) -> int:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO import_jobs (filename, total_rows, valid_rows, invalid_rows, duplicate_rows, uploaded_by)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (filename, total_rows, valid_rows, invalid_rows, duplicate_rows, uploaded_by)
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()
    return job_id

def insert_security_events(events: List[dict], import_job_id: int, db_path: Optional[str] = None) -> Tuple[int, int]:
    """Inserts clean security events. Returns (inserted_count, duplicate_count)."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    inserted = 0
    duplicates = 0

    for ev in events:
        try:
            cur.execute(
                """INSERT INTO security_events 
                   (import_job_id, timestamp, username, ip_address, login_result, event_type, device_info, country_code, hour_of_day, day_of_week, is_off_hours, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    import_job_id,
                    ev["timestamp"],
                    ev["username"],
                    ev["ip_address"],
                    ev["login_result"],
                    ev.get("event_type", "LOGIN"),
                    ev.get("device_info", "Standard Client"),
                    ev.get("country_code", "US"),
                    ev.get("hour_of_day", 12),
                    ev.get("day_of_week", 1),
                    1 if ev.get("is_off_hours") else 0,
                    ev["event_hash"]
                )
            )
            inserted += 1
        except sqlite3.IntegrityError:
            duplicates += 1

    conn.commit()
    conn.close()
    return inserted, duplicates

def get_security_events(
    limit: int = 100,
    offset: int = 0,
    username: Optional[str] = None,
    login_result: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db_path: Optional[str] = None
) -> Tuple[List[dict], int]:
    conn = get_connection(db_path)
    cur = conn.cursor()

    conditions = ["1=1"]
    params: List[Any] = []

    if username:
        conditions.append("username LIKE ?")
        params.append(f"%{username}%")
    if login_result and login_result != "ALL":
        conditions.append("login_result = ?")
        params.append(login_result)
    if start_date:
        conditions.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        conditions.append("timestamp <= ?")
        params.append(end_date)

    where_clause = " AND ".join(conditions)

    # Count total matching
    cur.execute(f"SELECT COUNT(*) FROM security_events WHERE {where_clause}", params)
    total_count = cur.fetchone()[0]

    # Query rows
    query = f"""
    SELECT id, import_job_id, timestamp, username, ip_address, login_result, event_type, device_info, country_code, is_off_hours
    FROM security_events 
    WHERE {where_clause} 
    ORDER BY timestamp DESC 
    LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows, total_count

def get_user_event_timeline(username: str, limit: int = 50, db_path: Optional[str] = None) -> List[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM security_events WHERE username = ? ORDER BY timestamp DESC LIMIT ?""",
        (username, limit)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_event_by_id(event_id: int, db_path: Optional[str] = None) -> Optional[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events WHERE id = ?", (event_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

# ----------------- ALERTS QUERIES -----------------

def create_alert(
    alert_id: str,
    event_id: int,
    username: str,
    detection_rule: str,
    detection_method: str,
    severity: str,
    reason: str,
    anomaly_score: Optional[float] = None,
    db_path: Optional[str] = None
) -> int:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO alerts (alert_id, event_id, username, detection_rule, detection_method, severity, anomaly_score, reason, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New')""",
        (alert_id, event_id, username, detection_rule, detection_method, severity, anomaly_score, reason)
    )
    aid = cur.lastrowid
    conn.commit()
    conn.close()
    return aid

def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    detection_method: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None
) -> Tuple[List[dict], int]:
    conn = get_connection(db_path)
    cur = conn.cursor()

    conditions = ["1=1"]
    params: List[Any] = []

    if status and status != "ALL":
        conditions.append("a.status = ?")
        params.append(status)
    if severity and severity != "ALL":
        conditions.append("a.severity = ?")
        params.append(severity)
    if detection_method and detection_method != "ALL":
        conditions.append("a.detection_method = ?")
        params.append(detection_method)
    if username:
        conditions.append("a.username LIKE ?")
        params.append(f"%{username}%")

    where_clause = " AND ".join(conditions)

    cur.execute(f"SELECT COUNT(*) FROM alerts a WHERE {where_clause}", params)
    total_count = cur.fetchone()[0]

    query = f"""
    SELECT a.*, e.timestamp as event_timestamp, e.ip_address, e.login_result, e.device_info, e.country_code
    FROM alerts a
    LEFT JOIN security_events e ON a.event_id = e.id
    WHERE {where_clause}
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows, total_count

def get_alert_by_id(alert_id_str: str, db_path: Optional[str] = None) -> Optional[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """SELECT a.*, e.timestamp as event_timestamp, e.ip_address, e.login_result, e.device_info, e.country_code
           FROM alerts a
           LEFT JOIN security_events e ON a.event_id = e.id
           WHERE a.alert_id = ?""",
        (alert_id_str,)
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def update_alert_status(alert_id_str: str, new_status: str, db_path: Optional[str] = None) -> bool:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "UPDATE alerts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE alert_id = ?",
        (new_status, alert_id_str)
    )
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def add_investigation_note(alert_primary_id: int, analyst: str, note: str, db_path: Optional[str] = None) -> int:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO investigation_notes (alert_id, analyst_username, note) VALUES (?, ?, ?)",
        (alert_primary_id, analyst, note)
    )
    nid = cur.lastrowid
    conn.commit()
    conn.close()
    return nid

def get_investigation_notes(alert_primary_id: int, db_path: Optional[str] = None) -> List[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM investigation_notes WHERE alert_id = ? ORDER BY created_at ASC",
        (alert_primary_id,)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

# ----------------- AUDIT & SETTINGS QUERIES -----------------

def log_audit_event(username: str, action: str, target_id: str, details: str, db_path: Optional[str] = None) -> None:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_history (username, action, target_id, details) VALUES (?, ?, ?, ?)",
        (username, action, target_id, details)
    )
    conn.commit()
    conn.close()

def get_recent_audit_logs(limit: int = 50, db_path: Optional[str] = None) -> List[dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_history ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_all_settings(db_path: Optional[str] = None) -> Dict[str, str]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT setting_key, setting_value FROM system_settings")
    settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}
    conn.close()
    return settings

def update_setting(key: str, value: str, db_path: Optional[str] = None) -> None:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO system_settings (setting_key, setting_value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP",
        (key, value)
    )
    conn.commit()
    conn.close()

# ----------------- DASHBOARD METRICS AGGREGATIONS -----------------

def get_dashboard_kpis(db_path: Optional[str] = None) -> Dict[str, Any]:
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM security_events")
    total_events = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM security_events WHERE login_result = 'SUCCESS'")
    success_events = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM security_events WHERE login_result = 'FAILURE'")
    failed_events = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT event_id) FROM alerts")
    suspicious_events = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Investigating')")
    open_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('Resolved', 'False Positive')")
    closed_alerts = cur.fetchone()[0]

    conn.close()

    return {
        "total_events": total_events,
        "success_events": success_events,
        "failed_events": failed_events,
        "suspicious_events": suspicious_events,
        "open_alerts": open_alerts,
        "closed_alerts": closed_alerts
    }

def get_events_timeseries(db_path: Optional[str] = None) -> pd.DataFrame:
    conn = get_connection(db_path)
    query = """
    SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket,
           login_result,
           COUNT(*) as event_count
    FROM security_events
    GROUP BY time_bucket, login_result
    ORDER BY time_bucket ASC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_alerts_distribution(db_path: Optional[str] = None) -> Dict[str, pd.DataFrame]:
    conn = get_connection(db_path)
    severity_df = pd.read_sql_query(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity", conn
    )
    method_df = pd.read_sql_query(
        "SELECT detection_method, COUNT(*) as count FROM alerts GROUP BY detection_method", conn
    )
    status_df = pd.read_sql_query(
        "SELECT status, COUNT(*) as count FROM alerts GROUP BY status", conn
    )
    conn.close()
    return {
        "severity": severity_df,
        "method": method_df,
        "status": status_df
    }
