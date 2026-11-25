from __future__ import annotations

import streamlit as st

from pages.common import badge_html, page_header
from reporting.report_generator import incident_report_data, render_html, render_markdown


def render(services) -> None:
    page_header("Security reports", "Generate a readable, record-derived investigation narrative with full evidence, findings, response status, and limitations.", eyebrow="Management / Investigation reporting")
    incidents = services.incidents.list()
    if not incidents:
        st.info("Create an incident before generating a report. No fabricated content is shown for an empty investigation registry.")
        return
    options = {item["incident_id"]: f"{item['incident_id']} · {item['title']} · {item['status']}" for item in incidents}
    preferred = st.query_params.get("incident_id") or st.session_state.get("active_incident_id")
    index = list(options).index(preferred) if preferred in options else 0
    incident_id = st.selectbox("Incident report", list(options), index=index, format_func=lambda value: options[value])
    incident = services.incidents.get(incident_id)
    with st.container(border=True):
        st.subheader(incident["title"])
        st.markdown(badge_html(incident["severity"]), unsafe_allow_html=True)
        st.text(f"{incident_id} · {incident['status']} · Created {incident['created_at']}")
    data = incident_report_data(services.database, incident_id)
    evidence_counts = sum(len(events) for events in data["evidence_by_alert"].values())
    metrics = st.columns(4)
    metrics[0].metric("Linked detections", len(data["alerts"]))
    metrics[1].metric("Supporting event rows", evidence_counts)
    metrics[2].metric("Analyst notes", len(data["notes"]))
    metrics[3].metric("Timeline entries", len(data["timeline"]))
    st.caption("Both export formats render the same shared report aggregate; no hardcoded findings or fabricated conclusions are inserted.")
    markdown = render_markdown(services.database, incident_id, data=data)
    html_export = render_html(services.database, incident_id, data=data)
    preview, methodology = st.tabs(["Formatted report preview", "Reporting methodology & export guidance"])
    with preview:
        st.markdown(markdown, unsafe_allow_html=False)
    with methodology:
        st.markdown("The report contains executive summary, incident overview, detection details, chronological timeline, supporting event evidence, analyst findings, recommended actions, incident status, and explicit limitations and uncertainties.")
        st.markdown("Imported events and analyst text remain escaped separately for Markdown and HTML formats. Both include status history, whether evidence is synthetic/public/manual/mixed, and the persistent resolution state without reconstructing stale conclusions.")
        st.info("Dedicated PDF export is not implemented. Download the print-friendly HTML and use the browser’s Print → Save as PDF for local PDF creation without an extra rendering service.")
    st.caption(f"Evidence origin label: {data['evidence_mode']}")
    columns = st.columns(2)
    columns[0].download_button("Download Markdown report", markdown.encode("utf-8"), f"{incident_id}.md", "text/markdown", use_container_width=True)
    columns[1].download_button("Download branded HTML report", html_export.encode("utf-8"), f"{incident_id}.html", "text/html", use_container_width=True)
