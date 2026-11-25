from __future__ import annotations

from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pandas as pd
import streamlit as st

from core.config import PROJECT_ROOT
from pages.common import page_header


def render(services) -> None:
    page_header("Settings & documentation", "Local operating preferences, demonstration controls, architecture guidance, security boundaries, and known limitations.")
    with st.form("application_preferences"):
        analyst = st.text_input("Default analyst name", value=services.settings.get("analyst_name", "Analyst"), max_chars=200)
        organisation = st.text_input("Organisation label (optional)", value=services.settings.get("organisation", "Educational demonstration"), max_chars=300)
        timezone = st.selectbox("Default display/naive-log timezone", ["Australia/Melbourne", "UTC", "Australia/Sydney", "Australia/Brisbane"], index=["Australia/Melbourne", "UTC", "Australia/Sydney", "Australia/Brisbane"].index(services.settings.get("timezone", "Australia/Melbourne")))
        reduced_motion = st.checkbox("Reduce animations and Plotly transitions", value=st.session_state.get("reduced_motion", False), key="settings_motion_preference")
        if st.form_submit_button("Save application settings", type="primary", use_container_width=True):
            try:
                ZoneInfo(timezone)
                if not analyst.strip():
                    raise ValueError("Analyst name cannot be empty")
                for key, value in (("analyst_name", analyst.strip()), ("organisation", organisation.strip()), ("timezone", timezone), ("reduced_motion", "true" if reduced_motion else "false")):
                    services.settings.set(key, value)
                services.ingestion.default_timezone = timezone
                services.metrics.zone = ZoneInfo(timezone)
                st.session_state["reduced_motion"] = reduced_motion
                st.success("Settings saved persistently.")
            except (ValueError, ZoneInfoNotFoundError) as error:
                st.error(str(error))
    st.subheader("Local status and Demo Mode")
    summary = services.metrics.summary()
    columns = st.columns(4)
    columns[0].metric("Stored events", f"{summary['total_events']:,}")
    columns[1].metric("Current alerts", f"{services.database.fetch_one('SELECT COUNT(*) AS count FROM security_alerts WHERE active = 1')['count']:,}")
    columns[2].metric("Incidents", len(services.incidents.list()))
    columns[3].metric("Vulnerabilities", len(services.vulnerabilities.list()))
    st.caption(f"Persistent SQLite database: {services.database.path}")
    if st.button("Load the complete simulated demonstration", use_container_width=True):
        with st.spinner("Loading 1,100 synthetic records and demonstration vulnerabilities…"):
            result = services.load_demonstration()
        st.session_state["demo_loaded"] = True
        st.success(f"{result['ingestion'].issue_summary}; {result['detection'].active} active findings. Re-imports are idempotent.")
    st.caption("Turning off the Demo Mode switch does not delete saved work. Data deletion is intentionally not exposed as routine interface action.")
    with st.expander("Security and privacy boundaries", expanded=True):
        st.markdown("- Uploads are size- and record-limited plain-text inputs; no uploaded command is executed.\n- Raw imported content is never passed to Streamlit raw-HTML rendering, and generated HTML reports escape all record fields.\n- Queries are parameterised; transactions and foreign keys enforce relational integrity.\n- No external network scanning, paid API, log forwarding, automatic firewall change, or containment occurs.\n- This is an educational monitoring workflow, not an enterprise SIEM, EDR, or vulnerability scanner.")
    documentation = {
        "Operator guide": PROJECT_ROOT / "docs" / "USER_GUIDE.md",
        "Detection model": PROJECT_ROOT / "docs" / "DETECTION_RULES.md",
        "Architecture": PROJECT_ROOT / "docs" / "ARCHITECTURE.md",
        "Dataset provenance": PROJECT_ROOT / "docs" / "DATASETS.md",
        "Three-minute demonstration": PROJECT_ROOT / "docs" / "THREE_MINUTE_DEMO.md",
        "Verification and limitations": PROJECT_ROOT / "docs" / "VERIFICATION.md",
    }
    selected = st.selectbox("Application documentation", list(documentation))
    path: Path = documentation[selected]
    if path.exists():
        st.markdown(path.read_text(encoding="utf-8"), unsafe_allow_html=False)
    else:
        st.info("Documentation file is not yet available in this installation.")
    with st.expander("Recent audit records"):
        audit = [dict(row) for row in services.database.fetch_all("SELECT * FROM audit_log ORDER BY created_at DESC, audit_id DESC LIMIT 50")]
        if audit:
            st.dataframe(pd.DataFrame(audit), use_container_width=True, hide_index=True)
        else:
            st.info("No audit entries have been recorded yet.")
