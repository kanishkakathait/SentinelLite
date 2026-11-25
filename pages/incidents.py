from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from core.config import INCIDENT_STATUSES, SEVERITIES
from investigations.timeline import incident_timeline
from pages.common import badge_html, metric_card, page_header, semantic_table_styles
from pages.investigation_workspace import render_incident_notes, render_timeline_entries
from pages.navigation import navigate_to


def incident_create_form(services) -> None:
    all_alerts = services.alerts.list(active_only=False)
    with st.expander("Create an incident from one or more alerts", expanded=not services.incidents.list()):
        if not all_alerts:
            st.info("Create an alert through ingestion and detection before opening an incident.")
            return
        options = {item["alert_id"]: f"{item['alert_id']} · {item['detection_name']} · {item['alert_timestamp']}" for item in all_alerts}
        default = st.session_state.get("incident_alert_ids", [])
        with st.form("new_incident_workspace"):
            selected = st.multiselect("Associated alerts", list(options), default=[item for item in default if item in options], format_func=lambda value: options[value], help="Select alerts explicitly. Correlation is an investigation lead, never automatic attack attribution.")
            title = st.text_input("Title", max_chars=300, placeholder="Suspected authentication anomaly requiring review")
            description = st.text_area("Description", max_chars=20_000, placeholder="Describe the observed evidence, scope, uncertainty, and why these alerts belong together.")
            severity = st.selectbox("Severity", SEVERITIES, index=2)
            actions = st.text_area("Initial recommended response actions", placeholder="Validate authorised access, review related telemetry, and document the outcome and outstanding uncertainty…")
            if st.form_submit_button("Create persistent incident", type="primary", use_container_width=True):
                try:
                    incident_id = services.incidents.create(title, description, severity, selected, actions)
                    st.session_state["active_incident_id"] = incident_id
                    st.session_state["incident_alert_ids"] = []
                    st.toast(f"Created {incident_id} as an Open incident")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))


def inspect_related_alert(alert_id: str) -> None:
    st.session_state["focused_alert_id"] = alert_id
    navigate_to("Security Alerts")


def render(services) -> None:
    page_header("Incident investigation", "Connect evidence, chronology, analyst judgement, and response documentation without implying automated containment.", eyebrow="Investigation / Evidence-led response")
    incident_create_form(services)
    incidents = services.incidents.list()
    if not incidents:
        st.info("No incidents have been created. Select one or more alerts above to begin a persistent investigation.")
        return
    by_id = {item["incident_id"]: item for item in incidents}
    preferred = st.query_params.get("incident_id") or st.session_state.get("active_incident_id")
    index = list(by_id).index(preferred) if preferred in by_id else 0
    incident_id = st.selectbox("Incident workspace", list(by_id), index=index, format_func=lambda value: f"{value} · {by_id[value]['title']} · {by_id[value]['status']}")
    st.session_state["active_incident_id"] = incident_id
    incident = services.incidents.get(incident_id)
    with st.container(border=True):
        st.subheader(incident["title"])
        st.markdown(badge_html(incident["severity"]), unsafe_allow_html=True)
        st.text(f"{incident_id} · {incident['status']} · Created {incident['created_at']}")
        st.text(incident["description"])
        st.button("Open incident report →", key=f"incident_report_{incident_id}", on_click=navigate_to, args=("Security Reports",))
    overview, visual_timeline, notes, response = st.tabs(["Incident & evidence", "Visual timeline", "Analyst notes", "Status & response"])
    with overview:
        metrics = [
            (f"incident_status_{incident_id}", "◎", "Investigation status", incident["status"], "Current persisted incident state", "neutral", None),
            (f"incident_severity_{incident_id}", "△", "Severity", incident["severity"].title(), "Current recorded incident severity", "warning", None),
            (f"incident_alerts_{incident_id}", "⚠", "Associated alerts", str(len(incident["alerts"])), "Explicitly selected by an analyst", "neutral", None),
            (f"incident_created_{incident_id}", "◷", "Created (UTC)", incident["created_at"][:10], incident["created_at"], "neutral", None),
        ]
        for column, arguments in zip(st.columns(4), metrics):
            with column:
                metric_card(*arguments)
        st.subheader("Affected entities")
        users, hosts, ips = st.columns(3)
        with users:
            st.text("Accounts")
            st.text(", ".join(json.loads(incident["affected_users_json"])) or "Not supplied")
        with hosts:
            st.text("Hosts / systems")
            st.text(", ".join(json.loads(incident["affected_hosts_json"])) or "Not supplied")
        with ips:
            st.text("Source IP addresses")
            st.text(", ".join(json.loads(incident["source_ips_json"])) or "Not supplied")
        if incident["recommended_actions"]:
            st.caption("Initial response recommendations (documentation only, not executed actions)")
            st.text(incident["recommended_actions"])
        st.subheader("Associated detections and evidence links")
        if incident["alerts"]:
            display = pd.DataFrame(incident["alerts"])
            st.dataframe(semantic_table_styles(display), use_container_width=True, hide_index=True)
            for alert in incident["alerts"]:
                st.button(f"Inspect {alert['detection_name']} · {alert['alert_id'][:14]}…", key=f"incident_alert_{alert['alert_id']}", on_click=inspect_related_alert, args=(alert["alert_id"],))
        else:
            st.info("No associated alerts remain in this incident record.")
        st.caption("Grouping is explicit and manually reviewed. Entity overlap and related alerts are investigation leads, not confirmed attacks.")
    with visual_timeline:
        entries = incident_timeline(services.database, incident_id)
        if entries:
            st.caption("Security events, detections, alert creation, and analyst activity are displayed in exact stored UTC order.")
            render_timeline_entries(entries, incident_id, services)
            with st.expander("Accessible full timeline table"):
                st.dataframe(pd.DataFrame(entries), use_container_width=True, hide_index=True)
                st.caption("All timestamps and evidence references are retained in this accessible alternative to the visual markers.")
        else:
            st.info("No timeline entries exist yet for this incident.")
    with notes:
        render_incident_notes(services, incident_id)
    with response:
        state_history = [dict(row) for row in services.database.fetch_all("SELECT previous_status, new_status, changed_at, note FROM status_history WHERE entity_type = 'incident' AND entity_id = ? ORDER BY changed_at, history_id", (incident_id,))]
        st.subheader("Investigation workflow")
        st.caption("New cases begin as Open. Supported persisted transitions are Open → Investigating → Contained → Resolved → Closed; reopening is audited.")
        with st.form(f"incident_status_{incident_id}"):
            current = INCIDENT_STATUSES.index(incident["status"])
            status = st.selectbox("Incident status", INCIDENT_STATUSES, index=current, help="Changing to Contained only documents your state assessment; no machines or accounts are isolated.")
            resolution = st.text_area("Resolution summary", value=incident["resolution_summary"], max_chars=20_000, placeholder="Required for Resolved or Closed: validated findings, actions completed outside SentinelLite, assumptions, and remaining uncertainty.")
            status_note = st.text_input("Status-change note", max_chars=500, placeholder="Why this persisted status is justified by the evidence.")
            if st.form_submit_button("Save status and resolution record", type="primary", use_container_width=True):
                try:
                    services.incidents.update_status(incident_id, status, resolution, status_note)
                    st.success("Incident status and resolution record saved.")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))
        st.subheader("Recorded status history")
        if state_history:
            st.dataframe(pd.DataFrame(state_history), use_container_width=True, hide_index=True)
        else:
            st.info("No incident status changes have been recorded yet.")
        st.info("Status and note changes are local documentation. No host isolation, address blocking, credential reset, or other external action is performed by these controls.")
