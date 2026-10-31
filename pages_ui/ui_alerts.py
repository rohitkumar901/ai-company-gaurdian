import streamlit as st
import pandas as pd
from core.auth import get_current_user
from core.notifier import send_alert_notification
from core.containment import (
    execute_ip_block_action,
    execute_user_suspension_action,
    execute_mfa_reset_action
)
from database.queries import (
    get_alerts,
    get_alert_by_id,
    update_alert_status,
    add_investigation_note,
    get_investigation_notes,
    log_audit_event
)

def render():
    st.title("🚨 Alerts & Incident Triage Queue")
    st.caption("Investigate, categorize, disposition incidents, and execute one-click automated containment playbooks.")

    current_user = get_current_user()

    # Filter controls
    with st.expander("🔍 Filter Incident Queue", expanded=True):
        fcol1, fcol2, fcol3, fcol4 = st.columns(4)
        with fcol1:
            status_filter = st.selectbox("Status", ["ALL", "New", "Investigating", "Resolved", "False Positive"], index=0)
        with fcol2:
            severity_filter = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], index=0)
        with fcol3:
            method_filter = st.selectbox("Detection Method", ["ALL", "RULE", "ML"], index=0)
        with fcol4:
            user_search = st.text_input("User Filter", placeholder="Search username...")

    alerts, total_count = get_alerts(
        status=status_filter,
        severity=severity_filter,
        detection_method=method_filter,
        username=user_search if user_search.strip() else None,
        limit=50
    )

    st.markdown(f"**Showing {len(alerts)} of {total_count} matching incidents**")

    if not alerts:
        st.info("No security incidents found matching the selected filter criteria.")
        return

    # Split screen: Left table, Right action pane
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.subheader("📋 Active Incident Queue")
        table_data = []
        for a in alerts:
            table_data.append({
                "Alert ID": a["alert_id"],
                "Severity": a["severity"],
                "Target User": a["username"],
                "MITRE ATT&CK": f"{a.get('mitre_technique_id', 'T1110')} - {a.get('mitre_technique_name', 'Brute Force')}",
                "Engine": a["detection_method"],
                "Status": a["status"]
            })
        st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)

    with col_right:
        st.subheader("🛠️ Incident Triage & SOAR Playbooks")
        alert_ids = [a["alert_id"] for a in alerts]
        selected_aid = st.selectbox("Select Incident to Inspect & Mitigate:", alert_ids)

        if selected_aid:
            alert = get_alert_by_id(selected_aid)
            if alert:
                st.markdown(f"#### Incident Dossier: `{alert['alert_id']}`")
                
                sev_color = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "blue"}.get(alert["severity"], "gray")
                st.markdown(f"**Severity:** :{sev_color}[{alert['severity']}] | **Engine:** `{alert['detection_method']}`")
                st.markdown(f"**Target Account:** `{alert['username']}` | **Origin IP:** `{alert.get('ip_address', 'N/A')}`")
                st.markdown(f"**MITRE ATT&CK:** `{alert.get('mitre_technique_id', 'T1110')}` — *{alert.get('mitre_technique_name', 'Brute Force')}* (`{alert.get('mitre_tactic', 'Credential Access')}`)")
                st.info(f"**Threat Intelligence Rationale:**\n{alert['reason']}")

                # SOAR Containment Playbooks
                st.markdown("#### ⚡ Active Containment Playbooks")
                col_act1, col_act2 = st.columns(2)
                with col_act1:
                    target_ip = alert.get("ip_address")
                    if target_ip and target_ip != "N/A":
                        if st.button("🚫 Block IP at Firewall", use_container_width=True):
                            res = execute_ip_block_action(target_ip, f"Automated SOAR block from {alert['alert_id']}", current_user["username"], alert["alert_id"])
                            if res["status"] == "success":
                                st.success(res["message"])
                            else:
                                st.warning(res["message"])

                with col_act2:
                    if st.button("🔒 Suspend User Account", use_container_width=True):
                        res = execute_user_suspension_action(alert["username"], f"Compromise containment from {alert['alert_id']}", current_user["username"], alert["alert_id"])
                        if res["status"] == "success":
                            st.success(res["message"])
                        else:
                            st.warning(res["message"])

                if st.button("🔑 Enforce Mandatory MFA Step-Up", use_container_width=True):
                    res = execute_mfa_reset_action(alert["username"], current_user["username"], alert["alert_id"])
                    st.success(res["message"])

                st.markdown("---")
                # Disposition & Status
                st.markdown("**Incident Lifecycle Status:**")
                status_options = ["New", "Investigating", "Resolved", "False Positive"]
                curr_idx = status_options.index(alert["status"]) if alert["status"] in status_options else 0
                new_status = st.selectbox("Assign Status:", status_options, index=curr_idx, key=f"status_{selected_aid}")

                if st.button("💾 Commit Status Transition", use_container_width=True):
                    if new_status != alert["status"]:
                        update_alert_status(alert["alert_id"], new_status)
                        log_audit_event(
                            current_user["username"],
                            "ALERT_STATUS_UPDATE",
                            alert["alert_id"],
                            f"Status changed from {alert['status']} to {new_status}"
                        )
                        st.success(f"Updated status of {alert['alert_id']} to '{new_status}'!")
                        st.rerun()

                # Dispatch Notification
                if st.button("📧 Dispatch SOC Incident Advisory Email", use_container_width=True):
                    res = send_alert_notification(alert, current_user["username"])
                    if res["status"] in ("success", "simulated"):
                        st.success(res["message"])
                    else:
                        st.error(res["message"])

                st.markdown("---")
                # Notes Section
                st.markdown("**Forensic Evidence Notes:**")
                notes = get_investigation_notes(alert["id"])
                if notes:
                    for n in notes:
                        st.info(f"**{n['analyst_username']}** ({n['created_at']}):\n{n['note']}")
                else:
                    st.caption("No notes recorded yet for this alert.")

                with st.form(f"note_form_{selected_aid}"):
                    new_note = st.text_area("Add Case Note:", placeholder="e.g. Verified with user via Slack; confirmed IP belongs to AWS proxy.")
                    add_btn = st.form_submit_button("➕ Post Note")
                    if add_btn and new_note.strip():
                        add_investigation_note(alert["id"], current_user["username"], new_note.strip())
                        log_audit_event(
                            current_user["username"],
                            "ADD_INVESTIGATION_NOTE",
                            alert["alert_id"],
                            f"Added note: {new_note.strip()[:60]}..."
                        )
                        st.success("Note added successfully!")
                        st.rerun()
