import streamlit as st
import pandas as pd
from database.queries import get_security_events

def render():
    st.title("🔍 Security Events Telemetry Explorer")
    st.caption("Search, filter, and inspect granular authentication events captured across the organization.")

    # Filter Bar
    with st.expander("🛠️ Filter & Query Controls", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            username_filter = st.text_input("Username Search", placeholder="e.g. charlie or david")
        with col2:
            result_filter = st.selectbox("Login Result", ["ALL", "SUCCESS", "FAILURE"], index=0)
        with col3:
            page_size = st.selectbox("Rows per page", [25, 50, 100], index=1)
        with col4:
            page_num = st.number_input("Page", min_value=1, value=1, step=1)

    offset = (page_num - 1) * page_size
    events, total_count = get_security_events(
        limit=page_size,
        offset=offset,
        username=username_filter if username_filter.strip() else None,
        login_result=result_filter
    )

    st.markdown(f"**Showing {len(events)} of {total_count:,} matching events** (Page {page_num} of {max(1, (total_count + page_size - 1) // page_size)})")

    if not events:
        st.info("No security events match your search criteria.")
        return

    # Render tabular view
    display_rows = []
    for ev in events:
        display_rows.append({
            "ID": ev["id"],
            "Timestamp": ev["timestamp"],
            "Username": ev["username"],
            "IP Address": ev["ip_address"],
            "Login Result": ev["login_result"],
            "Event Type": ev["event_type"],
            "Device": ev["device_info"][:35] + "..." if len(ev["device_info"]) > 35 else ev["device_info"],
            "Country": ev["country_code"],
            "Off Hours": "⚠️ Yes" if ev["is_off_hours"] else "No"
        })

    df = pd.DataFrame(display_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.caption("💡 To investigate suspicious logins associated with a specific user, copy their username and open **'Event Investigation'**.")
