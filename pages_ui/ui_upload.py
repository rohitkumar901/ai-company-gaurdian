import streamlit as st
import pandas as pd
from pathlib import Path
from config import BASE_DIR, DATA_DIR
from core.auth import get_current_user
from core.log_parser import parse_security_log_file
from core.rules import evaluate_detection_rules
from core.ml_detector import SecurityAnomalyDetector
from database.queries import (
    create_import_job,
    insert_security_events,
    create_alert,
    get_all_settings,
    log_audit_event,
    get_connection
)

def render():
    st.title("📥 Security Log Upload & Ingestion Engine")
    st.caption("Import enterprise authentication logs in CSV or JSON format, validate schema, normalize timestamps, and execute real-time threat detection.")

    current_user = get_current_user()
    settings = get_all_settings()

    tab1, tab2 = st.tabs(["📁 Upload File (CSV / JSON)", "⚡ Load Pre-configured Sample Dataset"])

    uploaded_file = None
    use_sample = False

    with tab1:
        st.write("Upload your authorized authentication logs:")
        uploaded_file = st.file_uploader(
            "Choose a CSV or JSON log file",
            type=["csv", "json"],
            help="File must contain: timestamp, username, ip_address, login_result"
        )
        st.markdown("""
        **Required Schema:**
        - `timestamp`: e.g. `2026-10-25 09:15:30`
        - `username`: e.g. `alice_dev`
        - `ip_address`: e.g. `192.168.1.101`
        - `login_result`: `SUCCESS` or `FAILURE`
        - *Optional*: `event_type`, `device_info`, `country_code`
        """)

    with tab2:
        st.write("Quickly evaluate the system using the pre-generated synthetic dataset containing benign logins, brute-force bursts, and credential stuffing attacks:")
        sample_path = DATA_DIR / "sample_auth_logs.csv"
        if sample_path.exists():
            sample_df = pd.read_csv(sample_path)
            st.dataframe(sample_df.head(5), use_container_width=True)
            if st.button("🚀 Ingest Synthetic Sample Dataset (193 Events)", type="primary"):
                use_sample = True
        else:
            st.warning("Sample dataset not found on disk. Please generate it first.")

    target_file = None
    filename = ""

    if uploaded_file is not None:
        target_file = uploaded_file
        filename = uploaded_file.name
    elif use_sample:
        target_file = str(sample_path)
        filename = "sample_auth_logs.csv"

    if target_file is not None:
        st.markdown("---")
        st.subheader("⚙️ Ingestion & Detection Controls")
        
        col1, col2 = st.columns(2)
        with col1:
            run_rules = st.checkbox("Execute Rule-Based Detection Engine", value=True)
            off_hours_start = int(settings.get("off_hours_start", 8))
            off_hours_end = int(settings.get("off_hours_end", 20))
            bf_thresh = int(settings.get("brute_force_failure_threshold", 5))
            bf_win = int(settings.get("brute_force_window_minutes", 10))

        with col2:
            run_ml = st.checkbox("Execute Machine Learning Anomaly Detector (Isolation Forest)", value=True)
            ml_thresh = float(settings.get("ml_anomaly_threshold", 0.65))

        if st.button("▶️ Process & Ingest Logs", type="primary", use_container_width=True):
            with st.spinner("Parsing logs, validating schema, and extracting telemetry..."):
                try:
                    # 1. Parse File
                    valid_records, invalid_records, summary = parse_security_log_file(
                        target_file,
                        filename,
                        off_hours_start=off_hours_start,
                        off_hours_end=off_hours_end
                    )

                    # 2. Record Import Job in DB
                    job_id = create_import_job(
                        filename=filename,
                        total_rows=summary["total_rows"],
                        valid_rows=summary["valid_rows"],
                        invalid_rows=summary["invalid_rows"],
                        duplicate_rows=0, # calculated next
                        uploaded_by=current_user["username"]
                    )

                    # 3. Insert Clean Events
                    inserted, duplicates = insert_security_events(valid_records, job_id)

                    # Update import job duplicate count
                    conn = get_connection()
                    conn.execute("UPDATE import_jobs SET duplicate_rows = ? WHERE id = ?", (duplicates, job_id))
                    conn.commit()
                    conn.close()

                    # Query back saved event IDs for mapping hashes
                    conn = get_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT id, event_hash FROM security_events WHERE import_job_id = ?", (job_id,))
                    hash_to_id = {r["event_hash"]: r["id"] for r in cur.fetchall()}
                    conn.close()

                    # 4. Run Detection Engines
                    alerts_created = 0

                    # A. Rule Engine
                    if run_rules:
                        rule_alerts = evaluate_detection_rules(
                            valid_records,
                            hash_to_id,
                            brute_force_thresh=bf_thresh,
                            brute_force_window_min=bf_win
                        )
                        for ra in rule_alerts:
                            create_alert(
                                alert_id=ra["alert_id"],
                                event_id=ra["event_id"],
                                username=ra["username"],
                                detection_rule=ra["detection_rule"],
                                detection_method=ra["detection_method"],
                                severity=ra["severity"],
                                reason=ra["reason"]
                            )
                            alerts_created += 1

                    # B. ML Engine
                    if run_ml:
                        detector = SecurityAnomalyDetector()
                        ml_alerts, _ = detector.predict_anomalies(
                            valid_records,
                            hash_to_id,
                            anomaly_threshold=ml_thresh
                        )
                        for ma in ml_alerts:
                            create_alert(
                                alert_id=ma["alert_id"],
                                event_id=ma["event_id"],
                                username=ma["username"],
                                detection_rule=ma["detection_rule"],
                                detection_method=ma["detection_method"],
                                severity=ma["severity"],
                                reason=ma["reason"],
                                anomaly_score=ma.get("anomaly_score")
                            )
                            alerts_created += 1

                    log_audit_event(
                        current_user["username"],
                        "LOG_IMPORT",
                        str(job_id),
                        f"Imported {filename}: {inserted} inserted, {duplicates} duplicate, {alerts_created} alerts generated."
                    )

                    st.success(f"🎉 Ingestion Complete! Successfully processed **{len(valid_records)}** events.")

                    # Ingestion Summary Box
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Total Records", summary["total_rows"])
                    c2.metric("Inserted Clean", inserted)
                    c3.metric("Duplicates Skipped", duplicates)
                    c4.metric("Threat Alerts Generated", alerts_created)

                    if invalid_records:
                        st.warning(f"⚠️ {len(invalid_records)} records failed validation. See details below:")
                        st.dataframe(pd.DataFrame(invalid_records), use_container_width=True)

                except Exception as e:
                    st.error(f"❌ Processing failed: {str(e)}")
