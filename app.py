import streamlit as st
from config import APP_NAME, APP_TAGLINE, APP_VERSION
from database.db import init_db
from core.auth import init_session_state, authenticate_user, login_user, logout_user, is_admin, get_current_user

# Ensure Database and Enterprise Schemas are initialized
init_db()

# Page Configuration
st.set_page_config(
    page_title=f"{APP_NAME} — Enterprise SIEM & SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Enterprise Dark SOC Dashboard Theme)
st.markdown("""
<style>
    /* Metric Card Styling */
    .metric-card {
        background-color: #1E293B;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #334155;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38BDF8;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 4px;
    }
    /* Severity Badges */
    .badge-critical { background-color: #7F1D1D; color: #FCA5A5; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #991B1B; color: #FECACA; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #9A3412; color: #FDBA74; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #1E3A8A; color: #93C5FD; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
init_session_state()

# ----------------- LOGIN SCREEN -----------------
if not st.session_state["authenticated"]:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown(f"<h1 style='text-align: center; color: #38BDF8;'>🛡️ {APP_NAME}</h1>", unsafe_allow_html=True)
        st.markdown(f"<p style='text-align: center; color: #94A3B8;'>{APP_TAGLINE}</p>", unsafe_allow_html=True)
        st.markdown(f"<p style='text-align: center;'><span style='background: #0284C7; color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem;'>{APP_VERSION}</span></p>", unsafe_allow_html=True)
        st.markdown("---")

        with st.form("login_form"):
            st.subheader("SOC Console Identity Authentication")
            username_input = st.text_input("Username", placeholder="e.g. admin or analyst")
            password_input = st.text_input("Password", type="password", placeholder="Enter credentials")
            submit_btn = st.form_submit_button("Authenticate to SIEM Console", use_container_width=True)

            if submit_btn:
                user = authenticate_user(username_input, password_input)
                if user:
                    login_user(user)
                    st.success(f"Identity verified for {user['username']} ({user['role'].upper()}). Launching console...")
                    st.rerun()
                else:
                    st.error("Authentication failed. Invalid identity credentials.")

        with st.expander("🔑 Default Access Credentials"):
            st.markdown("""
            - **Enterprise Administrator**: `admin` | Password: `Admin@Guardian2026` *(Full access + SOAR & User Management)*
            - **SOC Threat Analyst**: `analyst` | Password: `Analyst@Guardian2026` *(Investigation, MITRE correlation & Triage)*
            """)
    st.stop()

# ----------------- AUTHENTICATED SOC CONSOLE -----------------
current_user = get_current_user()

with st.sidebar:
    st.markdown(f"### 🛡️ **{APP_NAME}**")
    st.caption(f"Enterprise Edition • {APP_VERSION}")
    st.markdown("---")

    role_color = "red" if current_user['role'] == "admin" else "blue"
    st.markdown(f"**Operator:** `{current_user['username']}`")
    st.markdown(f"**Privilege:** :{role_color}[{current_user['role'].upper()}]")
    if st.button("🚪 Logout Console", use_container_width=True):
        logout_user()

    st.markdown("---")
    st.subheader("Operations Menu")

    menu_options = [
        "📊 Main SOC Dashboard",
        "📥 Ingest & Telemetry Engine",
        "🔍 Security Events Explorer",
        "🚨 Alerts & Incident Triage",
        "🕵️ Deep Event Investigation",
        "🛡️ SOAR Containment & Active Defense",
        "🤖 ML Anomaly Analysis Hub",
        "📑 Compliance Reports & Export",
        "⚙️ System Settings & Policy"
    ]

    if is_admin():
        menu_options.append("👥 Admin Identity Management")

    selected_page = st.radio("Go to:", menu_options, index=0)

# Page Routing
if selected_page == "📊 Main SOC Dashboard":
    from pages_ui import ui_dashboard
    ui_dashboard.render()

elif selected_page == "📥 Ingest & Telemetry Engine":
    from pages_ui import ui_upload
    ui_upload.render()

elif selected_page == "🔍 Security Events Explorer":
    from pages_ui import ui_events
    ui_events.render()

elif selected_page == "🚨 Alerts & Incident Triage":
    from pages_ui import ui_alerts
    ui_alerts.render()

elif selected_page == "🕵️ Deep Event Investigation":
    from pages_ui import ui_investigation
    ui_investigation.render()

elif selected_page == "🛡️ SOAR Containment & Active Defense":
    from pages_ui import ui_containment
    ui_containment.render()

elif selected_page == "🤖 ML Anomaly Analysis Hub":
    from pages_ui import ui_ml
    ui_ml.render()

elif selected_page == "📑 Compliance Reports & Export":
    from pages_ui import ui_reports
    ui_reports.render()

elif selected_page == "⚙️ System Settings & Policy":
    from pages_ui import ui_settings
    ui_settings.render()

elif selected_page == "👥 Admin Identity Management":
    from pages_ui import ui_admin
    ui_admin.render()
