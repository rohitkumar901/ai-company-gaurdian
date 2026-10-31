import streamlit as st
import pandas as pd
from core.auth import get_current_user, is_admin
from core.containment import (
    execute_ip_block_action,
    execute_user_suspension_action,
    generate_firewall_scripts
)
from database.queries import (
    list_blocked_ips,
    unblock_ip,
    list_suspended_accounts,
    reactivate_account,
    list_containment_actions,
    log_audit_event
)

def render():
    st.title("🛡️ SOAR Incident Response & Active Containment")
    st.caption("Automated and manual security orchestration: Block adversarial IPs at perimeter firewalls, isolate compromised identities, and inspect mitigation playbooks.")

    current_user = get_current_user()

    tab1, tab2, tab3, tab4 = st.tabs([
        "🚫 Blocked IPs (Firewall Denylist)",
        "🔒 Suspended Identity Accounts",
        "⚡ Manual Containment Dispatcher",
        "📜 Incident Playbook Execution Log"
    ])

    with tab1:
        st.subheader("Perimeter Firewall Active IP Blacklist")
        blocked = list_blocked_ips()
        if blocked:
            b_df = pd.DataFrame(blocked)
            st.dataframe(b_df[["id", "ip_address", "reason", "blocked_by", "created_at"]], use_container_width=True, hide_index=True)

            st.markdown("---")
            st.subheader("Manage Active Blocks & Generate Firewall Rules")
            ip_choices = [b["ip_address"] for b in blocked]
            selected_ip = st.selectbox("Select IP Address:", ip_choices)

            if selected_ip:
                col_rules, col_act = st.columns([3, 1])
                with col_rules:
                    st.markdown(f"**Enterprise Firewall Push Rules for `{selected_ip}`:**")
                    rules = generate_firewall_scripts(selected_ip)
                    for fw_type, cmd in rules.items():
                        st.code(cmd, language="bash")
                with col_act:
                    st.markdown("<br><br>", unsafe_allow_html=True)
                    if st.button(f"🔓 Lift Block (Allow {selected_ip})", type="secondary", use_container_width=True):
                        unblock_ip(selected_ip)
                        log_audit_event(current_user["username"], "UNBLOCK_IP", selected_ip, "Lifted firewall block.")
                        st.success(f"IP {selected_ip} removed from firewall blacklist.")
                        st.rerun()
        else:
            st.info("No IPs are currently blacklisted at perimeter firewalls.")

    with tab2:
        st.subheader("Suspended Identity Accounts Directory")
        suspended = list_suspended_accounts()
        if suspended:
            s_df = pd.DataFrame(suspended)
            st.dataframe(s_df[["id", "username", "reason", "suspended_by", "created_at"]], use_container_width=True, hide_index=True)

            st.markdown("---")
            user_choices = [s["username"] for s in suspended]
            selected_u = st.selectbox("Select User Account:", user_choices)
            if selected_u:
                if st.button(f"🔓 Reactivate Account '{selected_u}'", type="secondary"):
                    reactivate_account(selected_u)
                    log_audit_event(current_user["username"], "REACTIVATE_ACCOUNT", selected_u, "Reactivated user identity.")
                    st.success(f"Account '{selected_u}' reactivated in identity directory.")
                    st.rerun()
        else:
            st.info("No employee accounts are currently locked or suspended.")

    with tab3:
        st.subheader("Manual Threat Containment Dispatcher")
        st.caption("Apply emergency containment actions directly without waiting for automated rule triggers.")

        col_ip, col_usr = st.columns(2)
        with col_ip:
            st.markdown("#### 🚫 Quarantine IP Address")
            with st.form("manual_ip_block"):
                target_ip = st.text_input("IP Address to Block:", placeholder="e.g. 198.51.100.99")
                ip_reason = st.text_input("Containment Reason:", placeholder="Known C2 node / repeated attack burst")
                block_submit = st.form_submit_button("Execute Firewall Block", type="primary")

                if block_submit:
                    if not target_ip.strip():
                        st.error("Please enter a valid IP address.")
                    else:
                        res = execute_ip_block_action(target_ip.strip(), ip_reason.strip() or "Manual SOC Block", current_user["username"])
                        if res["status"] == "success":
                            st.success(res["message"])
                            st.rerun()
                        else:
                            st.error(res["message"])

        with col_usr:
            st.markdown("#### 🔒 Quarantine Compromised Account")
            with st.form("manual_user_suspend"):
                target_user = st.text_input("Account Username:", placeholder="e.g. david_ops")
                user_reason = st.text_input("Suspension Justification:", placeholder="Suspected token leakage / lateral movement")
                suspend_submit = st.form_submit_button("Suspend Identity", type="primary")

                if suspend_submit:
                    if not target_user.strip():
                        st.error("Please enter a valid username.")
                    else:
                        res = execute_user_suspension_action(target_user.strip(), user_reason.strip() or "Manual SOC Suspension", current_user["username"])
                        if res["status"] == "success":
                            st.success(res["message"])
                            st.rerun()
                        else:
                            st.error(res["message"])

    with tab4:
        st.subheader("SOC Incident Response Playbook Audit Log")
        st.caption("Chronological record of all defensive actions executed across enterprise infrastructure.")
        actions = list_containment_actions(limit=50)
        if actions:
            st.dataframe(pd.DataFrame(actions), use_container_width=True, hide_index=True)
        else:
            st.info("No containment actions recorded yet.")
