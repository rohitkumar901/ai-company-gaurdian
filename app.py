import streamlit as st
from config import APP_NAME, APP_TAGLINE, APP_VERSION
from database.db import init_db
from core.auth import init_session_state, authenticate_user, login_user, logout_user, is_admin, get_current_user

# Ensure Database is initialized
init_db()

# Page Configuration
st.set_page_config(
    page_title=f"{APP_NAME} — Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark SOC Dashboard Theme)
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
        font-size: 2rem;
        font-weight: 700;
        color: #38BDF8;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    /* Severity Badges */
    .badge-critical { background-color: #7F1D1D; color: #FCA5A5; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #991B1B; color: #FECACA; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #9A3412; color: #FDBA74; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #1E3A8A; color: #93C5FD; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    /* Success / Failure */
    .badge-success { background-color: #064E3B; color: #6EE7B7; padding: 3px 8px; border-radius: 4px; }
    .badge-failure { background-color: #831843; color: #F472B6; padding: 3px 8px; }
</style>
""", unsafe_allow_html=True)

# Initialize Session
init_session_state()

# ----------------- LOGIN SCREEN -----------------
if not st.session_state["authenticated"]:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown(f"<h1 style='text-align: center; color: #38BDF8;'>🛡️ {APP_NAME}</h1>", unsafe_allow_html=True)
        st.markdown(f"<p style='text-align: center; color: #94A3B8;'>{APP_TAGLINE}</p>", unsafe_allow_html=True)
        st.markdown("---")

        with st.form("login_form"):
            st.subheader("Sign In to Security Operations Console")
            username_input = st.text_input("Username", placeholder="e.g. admin or analyst")
            password_input = st.text_input("Password", type="password", placeholder="Enter credentials")
            submit_btn = st.form_submit_button("Access SOC Console", use_container_width=True)

            if submit_btn:
                user = authenticate_user(username_input, password_input)
                if user:
                    login_user(user)
                    st.success(f"Welcome back, {user['username']}! Loading dashboard...")
                    st.rerun()
                else:
                    st.error("Authentication failed. Please check username or password.")

        with st.expander("🔑 Default Demo Credentials"):
            st.markdown("""
            - **Admin User**: `admin` | Password: `Admin@Guardian2026` *(Full access + User Management)*
            - **Analyst User**: `analyst` | Password: `Analyst@Guardian2026` *(Investigation & Triage)*
            """)
    st.stop()

# ----------------- AUTHENTICATED CONSOLE -----------------
current_user = get_current_user()

# Sidebar
with st.sidebar:
    st.markdown(f"### 🛡️ **{APP_NAME}**")
    st.caption(f"v{APP_VERSION} • Prototype Edition")
    st.markdown("---")

    # Operator card
    role_color = "red" if current_user['role'] == "admin" else "blue"
    st.markdown(f"**Operator:** `{current_user['username']}`")
    st.markdown(f"**Role:** :{role_color}[{current_user['role'].upper()}]")
    if st.button("🚪 Logout", use_container_width=True):
        logout_user()

    st.markdown("---")
    st.subheader("Navigation")

    menu_options = [
        "📊 Main Dashboard",
        "📥 Upload & Ingest Logs",
        "🔍 Security Events Explorer",
        "🚨 Alerts & Incident Triage",
        "🕵️ Event Investigation",
        "🤖 ML Anomaly Analysis",
        "📑 Reports & Export",
        "⚙️ System Settings"
    ]

    # Admin only section
    if is_admin():
        menu_options.append("👥 Admin User Management")

    selected_page = st.radio("Go to:", menu_options, index=0)

# Page Routing
if selected_page == "📊 Main Dashboard":
    from pages_ui import ui_dashboard
    ui_dashboard.render()

elif selected_page == "📥 Upload & Ingest Logs":
    from pages_ui import ui_upload
    ui_upload.render()

elif selected_page == "🔍 Security Events Explorer":
    from pages_ui import ui_events
    ui_events.render()

elif selected_page == "🚨 Alerts & Incident Triage":
    from pages_ui import ui_alerts
    ui_alerts.render()

elif selected_page == "🕵️ Event Investigation":
    from pages_ui import ui_investigation
    ui_investigation.render()

elif selected_page == "🤖 ML Anomaly Analysis":
    from pages_ui import ui_ml
    ui_ml.render()

elif selected_page == "📑 Reports & Export":
    from pages_ui import ui_reports
    ui_reports.render()

elif selected_page == "⚙️ System Settings":
    from pages_ui import ui_settings
    ui_settings.render()

elif selected_page == "👥 Admin User Management":
    from pages_ui import ui_admin
    ui_admin.render()
