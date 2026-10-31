import streamlit as st
import pandas as pd
from datetime import datetime
from database.queries import (
    get_security_events,
    get_alerts,
    get_dashboard_kpis
)
from core.reporter import (
    export_events_to_csv,
    export_alerts_to_csv,
    generate_executive_summary_report
)
from core.auth import get_current_user

def render():
    st.title("📑 Security Reports & Intelligence Export")
    st.caption("Generate compliance and SOC incident audit reports, download filtered telemetry in CSV format, or build executive summaries.")

    current_user = get_current_user()
    kpis = get_dashboard_kpis()

    tab1, tab2, tab3 = st.tabs(["📄 Executive Incident Summary", "📊 Export Alerts (CSV)", "🔍 Export Raw Telemetry (CSV)"])

    with tab1:
        st.subheader("Executive SOC Audit Report")
        st.caption("Synthesizes overall authentication activity, priority threats, top targeted identities, and recommendations.")

        all_alerts, _ = get_alerts(limit=500)
        report_text = generate_executive_summary_report(
            kpis=kpis,
            alerts=all_alerts,
            generated_by=f"{current_user['username']} ({current_user['role'].upper()})"
        )

        st.download_button(
            label="📥 Download Executive Summary (Markdown .md)",
            data=report_text,
            file_name=f"security_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            type="primary"
        )

        st.markdown("---")
        st.markdown("### Report Preview:")
        st.markdown(report_text)

    with tab2:
        st.subheader("Export Security Alerts")
        st.caption("Export active and closed security incidents with investigation metadata.")

        all_alerts, total_al = get_alerts(limit=1000)
        if all_alerts:
            alerts_csv = export_alerts_to_csv(all_alerts)
            st.write(f"Ready to export **{len(all_alerts)}** alert records:")
            st.dataframe(pd.DataFrame(all_alerts).head(5), use_container_width=True)

            st.download_button(
                label="📥 Download Alerts CSV",
                data=alerts_csv,
                file_name=f"guardian_alerts_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                type="primary"
            )
        else:
            st.info("No alerts available to export.")

    with tab3:
        st.subheader("Export Security Events Telemetry")
        st.caption("Export filtered event logs for external SIEM integration or compliance archiving.")

        col1, col2 = st.columns(2)
        with col1:
            res_filter = st.selectbox("Filter Result", ["ALL", "SUCCESS", "FAILURE"], key="exp_res")
        with col2:
            export_limit = st.selectbox("Max Events", [100, 500, 1000, 5000], index=1)

        events, _ = get_security_events(limit=export_limit, login_result=res_filter)
        if events:
            events_csv = export_events_to_csv(events)
            st.write(f"Ready to export **{len(events)}** security events:")
            st.dataframe(pd.DataFrame(events).head(5), use_container_width=True)

            st.download_button(
                label="📥 Download Events CSV",
                data=events_csv,
                file_name=f"guardian_events_{datetime.utcnow().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                type="primary"
            )
        else:
            st.info("No events match your criteria.")
