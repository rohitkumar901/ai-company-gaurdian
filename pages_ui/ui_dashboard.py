import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from database.queries import (
    get_dashboard_kpis,
    get_events_timeseries,
    get_alerts_distribution,
    get_alerts
)

def render():
    st.title("📊 Security Operations Executive Dashboard")
    st.caption("Real-time telemetry and threat intelligence overview across enterprise authentication logs.")

    # 1. KPI Cards
    kpis = get_dashboard_kpis()
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{kpis['total_events']:,}</div>
            <div class="metric-label">Total Events</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #34D399;">{kpis['success_events']:,}</div>
            <div class="metric-label">Successful Logins</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #F87171;">{kpis['failed_events']:,}</div>
            <div class="metric-label">Failed Logins</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #FB923C;">{kpis['suspicious_events']:,}</div>
            <div class="metric-label">Suspicious Events</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #E879F9;">{kpis['open_alerts']:,}</div>
            <div class="metric-label">Open Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #94A3B8;">{kpis['closed_alerts']:,}</div>
            <div class="metric-label">Resolved Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if kpis['total_events'] == 0:
        st.info("💡 No logs imported yet. Go to **'Upload & Ingest Logs'** to import CSV or JSON authentication records or load the sample dataset!")
        return

    # 2. Charts Row 1: Time Series Activity
    st.subheader("📈 Authentication Activity & Login Trends Over Time")
    ts_df = get_events_timeseries()
    if not ts_df.empty:
        fig_ts = px.bar(
            ts_df,
            x="time_bucket",
            y="event_count",
            color="login_result",
            color_discrete_map={"SUCCESS": "#10B981", "FAILURE": "#EF4444"},
            barmode="group",
            labels={"time_bucket": "Time Bucket (Hourly)", "event_count": "Number of Logins", "login_result": "Result"}
        )
        fig_ts.update_layout(
            template="plotly_dark",
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_ts, use_container_width=True)

    # 3. Charts Row 2: Threat Distribution
    col_c1, col_c2, col_c3 = st.columns(3)
    dist = get_alerts_distribution()

    with col_c1:
        st.subheader("⚠️ Alerts by Severity")
        sev_df = dist["severity"]
        if not sev_df.empty:
            color_map = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EA580C",
                "MEDIUM": "#D97706",
                "LOW": "#2563EB"
            }
            fig_sev = px.pie(
                sev_df,
                names="severity",
                values="count",
                color="severity",
                color_discrete_map=color_map,
                hole=0.4
            )
            fig_sev.update_layout(template="plotly_dark", margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.caption("No alerts currently recorded.")

    with col_c2:
        st.subheader("🔬 Detection Method")
        method_df = dist["method"]
        if not method_df.empty:
            fig_meth = px.pie(
                method_df,
                names="detection_method",
                values="count",
                color_discrete_sequence=["#06B6D4", "#8B5CF6", "#EC4899"],
                hole=0.4
            )
            fig_meth.update_layout(template="plotly_dark", margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig_meth, use_container_width=True)
        else:
            st.caption("No alerts recorded.")

    with col_c3:
        st.subheader("📋 Triage Status")
        status_df = dist["status"]
        if not status_df.empty:
            fig_stat = px.bar(
                status_df,
                x="status",
                y="count",
                color="status",
                color_discrete_sequence=px.colors.qualitative.Safe
            )
            fig_stat.update_layout(template="plotly_dark", margin=dict(l=10, r=10, t=20, b=10), showlegend=False)
            st.plotly_chart(fig_stat, use_container_width=True)
        else:
            st.caption("No alerts recorded.")

    # 4. Recent Active Threats Table
    st.subheader("🚨 Priority Incident Queue (Recent Active Threats)")
    recent_alerts, _ = get_alerts(limit=5)
    if recent_alerts:
        alert_rows = []
        for a in recent_alerts:
            alert_rows.append({
                "Alert ID": a["alert_id"],
                "Timestamp": a["event_timestamp"] or a["created_at"],
                "User": a["username"],
                "Severity": a["severity"],
                "Method": a["detection_method"],
                "Rule": a["detection_rule"],
                "Status": a["status"]
            })
        st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)
        st.caption("💡 Tip: Navigate to **'Alerts & Incident Triage'** or **'Event Investigation'** to inspect context and resolve incidents.")
    else:
        st.success("✅ Clean security state: No active alerts currently recorded.")
