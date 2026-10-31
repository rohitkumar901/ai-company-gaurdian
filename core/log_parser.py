import json
import hashlib
import io
from datetime import datetime
from typing import Tuple, List, Dict, Any
import pandas as pd
from config import REQUIRED_COLUMNS, VALID_LOGIN_RESULTS, LOG_QUARANTINE_PATH

def compute_event_hash(timestamp: str, username: str, ip_address: str, login_result: str) -> str:
    """Generate a deterministic SHA-256 fingerprint for deduplication."""
    raw = f"{timestamp.strip()}|{username.strip().lower()}|{ip_address.strip()}|{login_result.strip().upper()}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def is_within_off_hours(dt: datetime, start_hour: int = 8, end_hour: int = 20) -> bool:
    """Return True if timestamp falls outside standard working hours (8 AM - 8 PM) or on weekends."""
    if dt.weekday() >= 5:  # Saturday or Sunday
        return True
    return dt.hour < start_hour or dt.hour >= end_hour

def parse_security_log_file(
    file_bytes_or_buffer: Any,
    filename: str,
    off_hours_start: int = 8,
    off_hours_end: int = 20
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Parse CSV or JSON security logs, validate columns, normalize timestamps,
    compute hashes, and classify off-hours.
    """
    filename_lower = filename.lower()
    valid_records: List[Dict[str, Any]] = []
    invalid_records: List[Dict[str, Any]] = []

    raw_df: pd.DataFrame
    try:
        if filename_lower.endswith(".csv"):
            raw_df = pd.read_csv(file_bytes_or_buffer)
        elif filename_lower.endswith(".json"):
            if isinstance(file_bytes_or_buffer, (bytes, bytearray)):
                content = json.loads(file_bytes_or_buffer.decode("utf-8"))
            elif hasattr(file_bytes_or_buffer, "read"):
                content = json.load(file_bytes_or_buffer)
            else:
                content = json.loads(file_bytes_or_buffer)
            raw_df = pd.DataFrame(content)
        else:
            raise ValueError(f"Unsupported file format. Please upload CSV or JSON.")
    except Exception as e:
        raise ValueError(f"Failed to read file: {str(e)}")

    # Check for missing required columns
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in raw_df.columns]
    if missing_cols:
        raise ValueError(f"Missing mandatory columns: {', '.join(missing_cols)}. Required columns: {', '.join(REQUIRED_COLUMNS)}")

    total_rows = len(raw_df)

    for index, row in raw_df.iterrows():
        row_dict = row.to_dict()
        row_num = index + 1
        errors = []

        # 1. Check Username
        username = str(row_dict.get("username", "")).strip()
        if not username or username.lower() == "nan":
            errors.append("Username is empty or missing")

        # 2. Check IP Address
        ip_addr = str(row_dict.get("ip_address", "")).strip()
        if not ip_addr or ip_addr.lower() == "nan":
            errors.append("IP Address is empty or missing")

        # 3. Check Login Result
        login_result = str(row_dict.get("login_result", "")).strip().upper()
        if login_result not in VALID_LOGIN_RESULTS:
            errors.append(f"Invalid login_result: '{login_result}'. Must be SUCCESS or FAILURE")

        # 4. Check & Parse Timestamp
        raw_ts = str(row_dict.get("timestamp", "")).strip()
        parsed_dt = None
        if not raw_ts or raw_ts.lower() == "nan":
            errors.append("Timestamp is missing")
        else:
            try:
                # Flexible parser using pandas to_datetime
                parsed_dt = pd.to_datetime(raw_ts).to_pydatetime()
            except Exception:
                errors.append(f"Unparseable timestamp format: '{raw_ts}'")

        if errors:
            invalid_records.append({
                "row_number": row_num,
                "raw_data": row_dict,
                "errors": errors
            })
            continue

        # Standardized ISO timestamp string
        std_timestamp_str = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")
        event_hash = compute_event_hash(std_timestamp_str, username, ip_addr, login_result)
        off_hours_flag = is_within_off_hours(parsed_dt, off_hours_start, off_hours_end)

        valid_records.append({
            "timestamp": std_timestamp_str,
            "username": username,
            "ip_address": ip_addr,
            "login_result": login_result,
            "event_type": str(row_dict.get("event_type", "LOGIN")).strip().upper(),
            "device_info": str(row_dict.get("device_info", "Standard Device")).strip(),
            "country_code": str(row_dict.get("country_code", "US")).strip().upper(),
            "hour_of_day": parsed_dt.hour,
            "day_of_week": parsed_dt.weekday(),
            "is_off_hours": off_hours_flag,
            "event_hash": event_hash
        })

    # Save invalid records to quarantine for auditing if any exist
    if invalid_records:
        try:
            with open(LOG_QUARANTINE_PATH, "w", encoding="utf-8") as qf:
                json.dump(invalid_records, qf, indent=2, default=str)
        except Exception:
            pass

    summary = {
        "filename": filename,
        "total_rows": total_rows,
        "valid_rows": len(valid_records),
        "invalid_rows": len(invalid_records)
    }

    return valid_records, invalid_records, summary
