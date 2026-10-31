import streamlit as st
import pandas as pd
import plotly.express as px
from database.queries import (
    get_alerts,
    get_alert_by_id,
    get_user_event_timeline,
    get_event_by_id,
    add_investigation_note,
    get_investigation_notes,
    update_alert_status,
    log_audit_event
)
from core.auth import get_current_user

def render():
    st.title("🕵️ Forensic Event & Threat Investigation")
    st.caption("Deep forensic dive: Correlate user timeline telemetry, examine device fingerprints, and build investigation dossiers.")

    current_user = get_current_user()

    # Step 1: Select or Search Alert/User
    col_sel1, col_sel2 = st.columns([2, 1])
    alerts, _ = get_alerts(limit=100)
    alert_choices = {f"{a['alert_id']} — {a['username']} ({a['severity']})": a["alert_id"] for a in alerts}

    with col_sel1:
        selected_display = st.selectbox("Choose Alert to Investigate:", list(alert_choices.keys()) if alert_choices else ["No alerts found"])

    if not alert_choices:
        st.info("No alerts are currently available for investigation.")
        return

    alert_id = alert_choices[selected_display]
    alert = get_alert_by_id(alert_id)
    if not alert:
        st.error("Alert not found.")
        return

    st.markdown("---")

    # Forensic Dossier Header
    st.subheader(f"🛡️ Case Dossier: `{alert['alert_id']}`")
    hcol1, hcol2, hcol3, hcol4 = st.columns(4)
    hcol1.metric("Target User", alert["username"])
    hcol2.metric("Severity", alert["severity"])
    hcol3.metric("Detection Engine", alert["detection_method"])
    hcol4.metric("Current Status", alert["status"])

    # Incident Details Box
    st.info(f"**Trigger Rationale:** {alert['reason']}")

    # Forensic Details Cards
    dcol1, dcol2 = st.columns(2)
    with dcol1:
        st.markdown("### 📋 Original Event Telemetry")
        st.markdown(f"- **Event Timestamp:** `{alert.get('event_timestamp', 'N/A')}`")
        st.markdown(f"- **Source IP Address:** `{alert.get('ip_address', 'N/A')}`")
        st.markdown(f"- **Origin Country:** `{alert.get('country_code', 'US')}`")
        st.markdown(f"- **Reported Login Result:** `{alert.get('login_result', 'N/A')}`")
        st.markdown(f"- **Device Fingerprint / User Agent:** `{alert.get('device_info', 'Unknown')}`")

    with dcol2:
        st.markdown("### 🧠 AI & Detection Intelligence")
        st.markdown(f"- **Rule Identifier:** `{alert['detection_rule']}`")
        st.markdown(f"- **Detection Method:** `{alert['detection_method']}`")
        score_val = alert.get("anomaly_score")
        score_display = f"{score_val:.4f} (High Outlier)" if score_val else "N/A (Rule Based)"
        st.markdown(f"- **Isolation Forest Anomaly Score:** `{score_display}`")
        st.markdown(f"- **First Flagged At:** `{alert['created_at']}`")
        st.markdown(f"- **Last Updated:** `{alert['updated_at']}`")

    st.markdown("---")

    # Chronological User Timeline
    st.subheader(f"⏳ Telemetry Timeline for User '{alert['username']}'")
    st.caption("Chronological history of recent logins for this account to detect anomalies or lateral movement.")
    timeline_events = get_user_event_timeline(alert["username"], limit=30)
    
    if timeline_events:
        t_df = pd.DataFrame(timeline_events)
        
        # Timeline scatter / bar chart
        t_df["timestamp_dt"] = pd.to_datetime(t_df["timestamp"])
        fig_time = px.scatter(
            t_df,
            x="timestamp_dt",
            y="ip_address",
            color="login_result",
            color_discrete_map={"SUCCESS": "#10B981", "FAILURE": "#EF4444"},
            hover_data=["login_result", "device_info", "country_code"],
            title=f"Login Events by IP & Time for {alert['username']}"
        )
        fig_time.update_layout(template="plotly_dark", height=280)
        st.plotly_chart(fig_time, use_container_width=True)

        display_t = t_df[["timestamp", "ip_address", "login_result", "country_code", "device_info"]]
        st.dataframe(display_t, use_container_width=True, hide_index=True)

    st.markdown("---")

    # Case Disposition & Notes
    col_n1, col_n2 = st.columns(2)
    with col_n1:
        st.subheader("📝 Case Notes & Forensic Log")
        notes = get_investigation_notes(alert["id"])
        if notes:
            for n in notes:
                st.chat_message("analyst").markdown(f"**{n['analyst_username']}** at `{n['created_at']}`:\n\n{n['note']}")
        else:
            st.caption("No forensic notes added yet.")

        with st.form("investigation_note_form"):
            new_note = st.text_area("Add Forensic Observation / Finding:", placeholder="Detail IP reputation, VPN checks, or user interview results...")
            submit_note = st.form_submit_button("Submit Finding")
            if submit_note and new_note.strip():
                add_investigation_note(alert["id"], current_user["username"], new_note.strip())
                log_audit_event(current_user["username"], "ADD_NOTE_INVESTIGATION", alert["alert_id"], new_note.strip()[:60])
                st.success("Note recorded.")
                st.rerun()

    with col_n2:
        st.subheader("⚖️ Final Case Disposition")
        status_choices = ["New", "Investigating", "Resolved", "False Positive"]
        cur_status = alert["status"]
        selected_status = st.selectbox("Assign Disposition:", status_choices, index=status_choices.index(cur_status) if cur_status in status_choices else 0)

        if st.button("Apply Disposition & Close Investigation", type="primary", use_container_width=True):
            update_alert_status(alert["alert_id"], selected_status)
            log_audit_event(
                current_user["username"],
                "ALERT_STATUS_UPDATE",
                alert["alert_id"],
                f"Disposition set to {selected_status}"
            )
            st.success(f"Disposition for {alert['alert_id']} updated to '{selected_status}'!")
            st.rerun()
