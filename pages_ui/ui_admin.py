import streamlit as st
import pandas as pd
from core.auth import is_admin, get_current_user
from database.queries import (
    list_all_users,
    create_user,
    update_user_password,
    delete_user,
    log_audit_event
)

def render():
    if not is_admin():
        st.error("⛔ Access Denied. Administrator privileges required to access User Management.")
        return

    st.title("👥 Admin Identity & Access Control (RBAC)")
    st.caption("Manage SOC analyst accounts, assign administrative privileges, and maintain credential policies.")

    current_user = get_current_user()

    tab1, tab2, tab3 = st.tabs(["📋 User Accounts Directory", "➕ Provision New User", "🔑 Reset Password / Manage Access"])

    with tab1:
        st.subheader("Configured Accounts")
        users = list_all_users()
        if users:
            df = pd.DataFrame(users)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No users found.")

    with tab2:
        st.subheader("Provision New SOC Operator")
        with st.form("create_user_form"):
            new_username = st.text_input("New Username:", placeholder="e.g. analyst_vikram")
            new_pass = st.text_input("Temporary Password:", type="password")
            role_choice = st.selectbox("Role Assignment:", ["analyst", "admin"], index=0)
            submit_user = st.form_submit_button("➕ Provision Account", type="primary")

            if submit_user:
                if not new_username.strip() or not new_pass.strip():
                    st.error("Username and password cannot be empty.")
                else:
                    success = create_user(new_username, new_pass, role_choice)
                    if success:
                        log_audit_event(
                            current_user["username"],
                            "CREATE_USER",
                            new_username.strip(),
                            f"Created user with role {role_choice}"
                        )
                        st.success(f"User '{new_username.strip()}' created successfully!")
                        st.rerun()
                    else:
                        st.error(f"User '{new_username.strip()}' already exists. Please pick another username.")

    with tab3:
        st.subheader("Credential Reset & Account Deprovisioning")
        users = list_all_users()
        user_list = [u["username"] for u in users]
        
        selected_user = st.selectbox("Select Target User Account:", user_list)

        col_reset, col_del = st.columns(2)
        with col_reset:
            st.markdown("#### Reset Password")
            with st.form(f"reset_form_{selected_user}"):
                new_pw = st.text_input("New Password:", type="password")
                reset_btn = st.form_submit_button("Reset Password")
                if reset_btn:
                    if len(new_pw.strip()) < 6:
                        st.error("Password must be at least 6 characters long.")
                    else:
                        ok = update_user_password(selected_user, new_pw.strip())
                        if ok:
                            log_audit_event(current_user["username"], "RESET_PASSWORD", selected_user, "Password updated.")
                            st.success(f"Password for '{selected_user}' updated!")
                        else:
                            st.error("Failed to update password.")

        with col_del:
            st.markdown("#### Deprovision Account")
            if selected_user == "admin":
                st.info("🛡️ Primary admin account cannot be deprovisioned.")
            else:
                st.warning(f"Permanently remove user `{selected_user}` from the system?")
                if st.button(f"🗑️ Delete {selected_user}", type="primary"):
                    del_ok = delete_user(selected_user)
                    if del_ok:
                        log_audit_event(current_user["username"], "DELETE_USER", selected_user, "Account removed.")
                        st.success(f"User '{selected_user}' has been deprovisioned.")
                        st.rerun()
                    else:
                        st.error("Failed to delete user.")
