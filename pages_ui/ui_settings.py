import streamlit as st
import pandas as pd
from database.queries import (
    get_all_settings,
    update_setting,
    get_recent_audit_logs,
    log_audit_event
)
from core.auth import get_current_user, is_admin

def render():
    st.title("⚙️ System Configuration & Audit Trail")
    st.caption("Customize detection thresholds, schedule working hours, adjust ML sensitivity, and review system audit trails.")

    current_user = get_current_user()
    settings = get_all_settings()

    tab1, tab2 = st.tabs(["🔧 Policy & Threshold Settings", "📜 Operational Audit Log"])

    with tab1:
        st.subheader("Security Rules & Thresholds")
        if not is_admin():
            st.warning("🔒 Note: You are logged in as Analyst. Configuration settings can only be modified by an Admin. Showing view-only mode.")

        with st.form("settings_form"):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### 1. Rule-Based Threat Thresholds")
                bf_limit = st.number_input(
                    "Brute-Force Failed Attempts Threshold:",
                    min_value=2,
                    max_value=50,
                    value=int(settings.get("brute_force_failure_threshold", 5)),
                    disabled=not is_admin()
                )
                bf_window = st.number_input(
                    "Brute-Force Window (Minutes):",
                    min_value=1,
                    max_value=60,
                    value=int(settings.get("brute_force_window_minutes", 10)),
                    disabled=not is_admin()
                )
                spray_limit = st.number_input(
                    "Password Spraying Failure Threshold:",
                    min_value=3,
                    max_value=100,
                    value=int(settings.get("ip_spray_threshold", 10)),
                    disabled=not is_admin()
                )

            with c2:
                st.markdown("#### 2. Working Hours Policy")
                work_start = st.slider(
                    "Expected Business Hours Start (Hour 0-23):",
                    min_value=0,
                    max_value=23,
                    value=int(settings.get("off_hours_start", 8)),
                    disabled=not is_admin()
                )
                work_end = st.slider(
                    "Expected Business Hours End (Hour 0-23):",
                    min_value=0,
                    max_value=23,
                    value=int(settings.get("off_hours_end", 20)),
                    disabled=not is_admin()
                )

            st.markdown("---")
            st.markdown("#### 3. Machine Learning Sensitivity")
            mc1, mc2 = st.columns(2)
            with mc1:
                ml_thresh = st.slider(
                    "Anomaly Alert Threshold Cutoff (0.0 - 1.0):",
                    min_value=0.40,
                    max_value=0.95,
                    value=float(settings.get("ml_anomaly_threshold", 0.65)),
                    step=0.05,
                    disabled=not is_admin()
                )
            with mc2:
                ml_contam = st.slider(
                    "Isolation Forest Contamination Rate:",
                    min_value=0.01,
                    max_value=0.20,
                    value=float(settings.get("ml_contamination_rate", 0.05)),
                    step=0.01,
                    disabled=not is_admin()
                )

            st.markdown("---")
            st.markdown("#### 4. Email / SMTP Notifications")
            nc1, nc2 = st.columns(2)
            with nc1:
                smtp_active = st.checkbox(
                    "Enable Real SMTP Email Dispatch (Default: False for dev)",
                    value=settings.get("smtp_enabled", "False").lower() in ("true", "1", "yes"),
                    disabled=not is_admin()
                )
                smtp_server = st.text_input("SMTP Server:", value=settings.get("smtp_server", "smtp.example.com"), disabled=not is_admin())
            with nc2:
                smtp_recipient = st.text_input("Recipient Alert Email:", value=settings.get("smtp_recipient", "soc-team@company.internal"), disabled=not is_admin())
                smtp_port = st.number_input("SMTP Port:", value=int(settings.get("smtp_port", 587)), disabled=not is_admin())

            if is_admin():
                save_btn = st.form_submit_button("💾 Save System Configuration", type="primary")
                if save_btn:
                    update_setting("brute_force_failure_threshold", str(bf_limit))
                    update_setting("brute_force_window_minutes", str(bf_window))
                    update_setting("ip_spray_threshold", str(spray_limit))
                    update_setting("off_hours_start", str(work_start))
                    update_setting("off_hours_end", str(work_end))
                    update_setting("ml_anomaly_threshold", str(ml_thresh))
                    update_setting("ml_contamination_rate", str(ml_contam))
                    update_setting("smtp_enabled", str(smtp_active))
                    update_setting("smtp_server", str(smtp_server))
                    update_setting("smtp_recipient", str(smtp_recipient))
                    update_setting("smtp_port", str(smtp_port))

                    log_audit_event(
                        current_user["username"],
                        "UPDATE_SETTINGS",
                        "CONFIG",
                        f"Updated thresholds: BF={bf_limit}, OffHours={work_start}-{work_end}, ML_Cutoff={ml_thresh}"
                    )
                    st.success("✅ Application configuration updated successfully!")
                    st.rerun()

    with tab2:
        st.subheader("System Audit History")
        st.caption("Immutable record of user logins, log imports, status transitions, and setting modifications.")
        audit_logs = get_recent_audit_logs(limit=100)
        if audit_logs:
            st.dataframe(pd.DataFrame(audit_logs), use_container_width=True, hide_index=True)
        else:
            st.info("No audit logs recorded yet.")
