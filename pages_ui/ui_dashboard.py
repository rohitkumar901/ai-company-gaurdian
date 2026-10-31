import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from database.queries import (
    get_dashboard_kpis,
    get_events_timeseries,
    get_alerts_distribution,
    get_mitre_summary,
    get_alerts
)
from core.live_stream import ingest_live_batch

def render():
    st.title("📊 Security Operations Center (SOC) Executive Command Center")
    st.caption("Enterprise real-time authentication intelligence, MITRE ATT&CK telemetry correlation, and active containment posture.")

    # 1. Real-Time Telemetry Control Bar
    with st.container():
        ctrl1, ctrl2, ctrl3 = st.columns([2, 1, 1])
        with ctrl1:
            st.markdown("🔴 **Live SOC Feed:** Telemetry stream active and monitoring perimeter endpoints.")
        with ctrl2:
            if st.button("⚡ Inject Live Telemetry Packet (5 Events)", use_container_width=True):
                res = ingest_live_batch(5)
                st.toast(f"Ingested 5 live events. Generated {res['alerts_generated']} new threat alerts!")
                st.rerun()
        with ctrl3:
            if st.button("🔄 Refresh Telemetry Dashboard", use_container_width=True):
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. 8 Executive Metric Cards
    kpis = get_dashboard_kpis()
    r1_c1, r1_c2, r1_c3, r1_c4 = st.columns(4)
    with r1_c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{kpis['total_events']:,}</div>
            <div class="metric-label">Total Telemetry Ingested</div>
        </div>
        """, unsafe_allow_html=True)
    with r1_c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #34D399;">{kpis['success_events']:,}</div>
            <div class="metric-label">Authorized Logins</div>
        </div>
        """, unsafe_allow_html=True)
    with r1_c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #F87171;">{kpis['failed_events']:,}</div>
            <div class="metric-label">Failed Authentications</div>
        </div>
        """, unsafe_allow_html=True)
    with r1_c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #FB923C;">{kpis['suspicious_events']:,}</div>
            <div class="metric-label">Suspicious Anomalies</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    r2_c1, r2_c2, r2_c3, r2_c4 = st.columns(4)
    with r2_c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #E879F9;">{kpis['open_alerts']:,}</div>
            <div class="metric-label">Open Active Incidents</div>
        </div>
        """, unsafe_allow_html=True)
    with r2_c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #94A3B8;">{kpis['closed_alerts']:,}</div>
            <div class="metric-label">Resolved / Mitigated</div>
        </div>
        """, unsafe_allow_html=True)
    with r2_c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #EF4444;">{kpis['blocked_ips_count']:,}</div>
            <div class="metric-label">Blocked Perimeter IPs</div>
        </div>
        """, unsafe_allow_html=True)
    with r2_c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #FBBF24;">{kpis['suspended_accounts_count']:,}</div>
            <div class="metric-label">Quarantined Identities</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if kpis['total_events'] == 0:
        st.info("💡 No logs imported yet. Go to **'Upload & Ingest Logs'** to import CSV or JSON records or load the sample dataset!")
        return

    # 3. MITRE ATT&CK Matrix Breakdown (Enterprise Feature)
    st.subheader("🎯 MITRE ATT&CK® Enterprise Threat Matrix")
    mitre_df = get_mitre_summary()
    if not mitre_df.empty:
        col_m1, col_m2 = st.columns([3, 2])
        with col_m1:
            fig_mitre = px.bar(
                mitre_df,
                x="hit_count",
                y="mitre_technique_name",
                color="mitre_tactic",
                orientation="h",
                text="hit_count",
                labels={"hit_count": "Triggered Incidents", "mitre_technique_name": "Technique Name", "mitre_tactic": "ATT&CK Tactic"},
                color_discrete_sequence=px.colors.qualitative.Dark24
            )
            fig_mitre.update_layout(
                template="plotly_dark",
                margin=dict(l=10, r=20, t=20, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_mitre, use_container_width=True)

        with col_m2:
            st.markdown("#### Top Observed Tactics & Techniques:")
            for _, r in mitre_df.head(4).iterrows():
                st.markdown(f"- **`{r['mitre_technique_id']}` {r['mitre_technique_name']}**: `{r['hit_count']}` hits (*{r['mitre_tactic']}*)")
            st.caption("Correlated automatically from live authentication logs against MITRE ATT&CK v14 framework.")

    st.markdown("---")

    # 4. Telemetry Activity Trends
    st.subheader("📈 Hourly Authentication Telemetry Trends")
    ts_df = get_events_timeseries()
    if not ts_df.empty:
        fig_ts = px.bar(
            ts_df,
            x="time_bucket",
            y="event_count",
            color="login_result",
            color_discrete_map={"SUCCESS": "#10B981", "FAILURE": "#EF4444"},
            barmode="group",
            labels={"time_bucket": "Time Bucket (Hourly)", "event_count": "Volume", "login_result": "Result"}
        )
        fig_ts.update_layout(
            template="plotly_dark",
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_ts, use_container_width=True)

    # 5. Severity & Method Distributions
    col_c1, col_c2, col_c3 = st.columns(3)
    dist = get_alerts_distribution()

    with col_c1:
        st.subheader("⚠️ Severity Triage")
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

    with col_c2:
        st.subheader("🔬 Detection Engine")
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

    with col_c3:
        st.subheader("📋 Triage Lifecycle")
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

    # 6. Priority Incident Queue
    st.subheader("🚨 Priority Incident Queue (Recent Active Threats)")
    recent_alerts, _ = get_alerts(limit=6)
    if recent_alerts:
        alert_rows = []
        for a in recent_alerts:
            alert_rows.append({
                "Incident ID": a["alert_id"],
                "Timestamp": a["event_timestamp"] or a["created_at"],
                "Target Account": a["username"],
                "Severity": a["severity"],
                "MITRE Technique": f"{a.get('mitre_technique_id', 'T1110')} ({a.get('mitre_technique_name', 'Brute Force')})",
                "Engine": a["detection_method"],
                "Status": a["status"]
            })
        st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)
