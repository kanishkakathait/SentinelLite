from __future__ import annotations

import html
import json
from typing import Any

import pandas as pd
import streamlit as st

from core.activity import recent_activity
from core.config import ALERT_STATUSES, PROJECT_ROOT, SEVERITIES
from core.navigation import NAV_BY_LABEL
from pages.navigation import navigate_to

SEVERITY_COLOURS = {
    "critical": "#FB8B8B", "high": "#FBA45F", "medium": "#F1CB69",
    "low": "#65C7EC", "informational": "#A2B3C7",
}
CHART_LAYOUT = {
    "paper_bgcolor": "rgba(0,0,0,0)", "plot_bgcolor": "rgba(0,0,0,0)",
    "font": {"color": "#C3D4E7", "family": "Inter, Avenir, Helvetica, sans-serif"},
    "margin": {"l": 20, "r": 20, "t": 35, "b": 20},
    "legend": {"title": None}, "hoverlabel": {"bgcolor": "#132944", "font_size": 13},
    "transition": {"duration": 250},
}
STATUS_COLOURS = {
    "new": "#A2B3C7", "open": "#A2B3C7", "investigating": "#C4B6FC", "in progress": "#C4B6FC",
    "contained": "#73DFBD", "resolved": "#73DFBD", "remediated": "#73DFBD", "verified": "#73DFBD",
    "closed": "#B5BDCB", "false positive": "#B5BDCB", "superseded": "#B5BDCB", "active": "#65C7EC",
}
BADGE_TONES = {
    "critical", "high", "medium", "low", "informational", "neutral", "new", "open",
    "investigating", "in-progress", "contained", "resolved", "remediated", "verified",
    "closed", "false-positive", "superseded",
}


def brand_logo() -> str:
    return (PROJECT_ROOT / "assets" / "brand.svg").read_text(encoding="utf-8")


def page_header(title: str, subtitle: str, eyebrow: str = "Security operations") -> None:
    st.markdown(
        '<div class="heading-row">'
        f'<p class="eyebrow">{html.escape(eyebrow)}</p>'
        f'<h1>{html.escape(title)}</h1>'
        f'<p class="heading-subtitle">{html.escape(subtitle)}</p></div>',
        unsafe_allow_html=True,
    )


def style_chart(figure):
    layout = dict(CHART_LAYOUT)
    layout["transition"] = {"duration": 0 if st.session_state.get("reduced_motion", False) else 250}
    figure.update_layout(**layout)
    figure.update_xaxes(gridcolor="#253752", zeroline=False, linecolor="#3B506D")
    figure.update_yaxes(gridcolor="#253752", zeroline=False, linecolor="#3B506D")
    return figure


def section_heading(title: str, caption: str = "", icon: str = "◈") -> None:
    st.markdown(
        '<div class="section-heading">'
        f'<h2>{html.escape(icon)}&nbsp; {html.escape(title)}</h2>'
        f'<span class="section-heading-caption">{html.escape(caption)}</span></div>',
        unsafe_allow_html=True,
    )


def badge_html(value: str, kind: str = "severity") -> str:
    normalised = str(value).strip().lower().replace(" ", "-") if value else "neutral"
    badge_class = normalised if normalised in BADGE_TONES else "neutral"
    return f'<span class="badge badge-{badge_class}">{html.escape(str(value), quote=True)}</span>'


def show_badge(value: str, kind: str = "severity") -> None:
    st.markdown(badge_html(value, kind), unsafe_allow_html=True)


def metric_card(
    key: str,
    icon: str,
    label: str,
    value: str,
    help_text: str,
    tone: str = "neutral",
    target_page: str | None = None,
) -> None:
    value_text = str(value)
    state_key = f"kpi_previous_{key}"
    previous = st.session_state.get(state_key)
    changed = previous is not None and str(previous) != value_text
    with st.container(border=False):
        st.markdown(
            '<div class="kpi-shell">'
            f'<div class="kpi-top"><span class="kpi-label">{html.escape(label)}</span>'
            f'<span class="kpi-icon" aria-hidden="true">{html.escape(icon)}</span></div>'
            f'<div class="kpi-number{(" updated" if changed else "")}" data-tone="{html.escape(tone)}">{html.escape(value_text)}</div>'
            '</div>', unsafe_allow_html=True,
        )
        st.caption(help_text)
        if target_page and target_page in NAV_BY_LABEL:
            link_label = {"Security Events": "View events →", "Security Alerts": "View alerts →", "Threat Detection": "View detections →", "Incident Investigation": "View investigations →"}.get(target_page, "Explore →")
            st.button(
                link_label,
                key=f"kpi_link_{key}", on_click=navigate_to, args=(target_page,),
                use_container_width=True, help=f"Navigate to {target_page}",
            )
    st.session_state[state_key] = value_text


def short_id(identifier: str, visible: int = 13) -> str:
    return identifier if len(identifier) <= visible else f"{identifier[:visible]}…"


def semantic_table_styles(frame: pd.DataFrame):
    styled = frame.style
    for column in ("severity", "status", "remediation_status"):
        if column not in frame.columns:
            continue
        styles = SEVERITY_COLOURS if column == "severity" else STATUS_COLOURS
        values = {**SEVERITY_COLOURS, **STATUS_COLOURS} if column == "status" else styles
        styled = styled.map(
            lambda value, palette=values: f"color: {palette.get(str(value).lower(), '#C7D6E7')}; font-weight: 650;",
            subset=[column],
        )
    return styled


def event_rows(events) -> list[dict[str, Any]]:
    return [{
        "event_id": event.event_id, "timestamp": event.timestamp.isoformat(),
        "event_source": event.event_source, "hostname": event.hostname,
        "source_ip": event.source_ip, "destination_ip": event.destination_ip,
        "username": event.username, "event_category": event.event_category,
        "event_action": event.event_action, "authentication_result": event.authentication_result,
        "raw_message": event.raw_message, "simulated": event.simulated,
    } for event in events]


def render_events(events, key: str) -> None:
    rows = event_rows(events)
    if not rows:
        st.info("No supporting events are available.")
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, key=key)
    with st.expander("Inspect raw evidence safely"):
        selected = st.selectbox("Event ID", [row["event_id"] for row in rows], key=f"{key}_raw_event")
        event = next(row for row in rows if row["event_id"] == selected)
        st.text(f"Timestamp: {event['timestamp']} | Source: {event['source_ip'] or 'Not supplied'} | User: {event['username'] or 'Not supplied'}")
        st.code(event["raw_message"], language="text", wrap_lines=True)


def inspect_activity() -> None:
    entry = st.session_state.get("activity_focus")
    if not entry:
        return
    with st.expander("Selected activity detail", expanded=True):
        st.text(f"{entry['label']} · {entry['timestamp']}")
        st.text(entry["detail"])
        st.text(f"Full evidence reference: {entry['reference']}")
        if entry["raw_message"]:
            st.code(entry["raw_message"], language="text", wrap_lines=True)
        destination = {
            "alert": "Security Alerts", "incident": "Incident Investigation",
            "event": "Security Events", "vulnerability": "Vulnerability & Risk Register",
        }[entry["target"]]
        def open_detail() -> None:
            if entry["target"] == "alert":
                st.session_state["focused_alert_id"] = entry["reference"]
            elif entry["target"] == "incident":
                st.session_state["active_incident_id"] = entry["reference"]
            navigate_to(destination)
        st.button("Open in investigation workspace", key="activity_open_full", on_click=open_detail)


def render_activity_feed(services, limit: int = 8) -> None:
    entries = recent_activity(services.database, limit=limit)
    if not entries:
        st.info("No persisted security activity is available yet.")
        return
    for index, entry in enumerate(entries):
        with st.container(border=True):
            st.markdown(f'<div class="activity-row"><span class="activity-marker {html.escape(entry["kind"])}"></span><div class="activity-content">{html.escape(entry["label"])}<div class="activity-meta">{html.escape(entry["timestamp"])} · {html.escape(entry["detail"])}</div></div></div>', unsafe_allow_html=True)
            def inspect(entry=entry) -> None:
                st.session_state["activity_focus"] = entry
            identifier = "".join(character for character in entry["reference"] if character.isalnum())[:20]
            st.button("Inspect activity", key=f"activity_{index}_{identifier}", on_click=inspect)


def _related_leads(services, alert: dict[str, Any]) -> None:
    related = services.alerts.related(alert["alert_id"]) if hasattr(services.alerts, "related") else []
    with st.expander("Investigation leads · related entity matches", expanded=False):
        if not related:
            st.text("No other alerts share a recorded source IP, account, or hostname. This is not evidence that activity is unrelated.")
            return
        st.text("Entity overlap is an investigation lead, not a conclusion that alerts are part of the same attack.")
        for item in related:
            shared = [field for field in ("source_ip", "username", "hostname") if alert.get(field) and alert[field] == item.get(field)]
            with st.container(border=True):
                st.text(f"{item['detection_name']} · {item['timestamp'] if 'timestamp' in item else item['alert_timestamp']}")
                st.text(f"{item['alert_id']} · {item['severity']} · {item['status']}")
                st.text(f"Shared with this alert: {', '.join(shared)}")
                def focus_related(alert_id=item["alert_id"]) -> None:
                    st.session_state["focused_alert_id"] = alert_id
                    navigate_to("Security Alerts")
                st.button(f"Inspect {short_id(item['alert_id'])}", key=f"related_{alert['alert_id']}_{item['alert_id']}", on_click=focus_related)


def render_alert_workspace(services, alert_id: str, key_prefix: str) -> None:
    alert = services.alerts.get(alert_id)
    st.subheader(f"{alert['detection_name']} · {short_id(alert_id)}")
    with st.container(border=True):
        show_badge(alert["severity"])
        st.text(f"{alert['rule_id']} · {alert['detection_name']}")
        st.text(f"Full alert ID: {alert_id}")
        st.text(f"Detection timestamp (UTC): {alert['alert_timestamp']}")
        st.text(f"Source: {alert['source_ip'] or 'Not supplied'} · Account: {alert['username'] or 'Multiple/not supplied'} · Host: {alert['hostname'] or 'Multiple/not supplied'}")
        st.text(f"State: {alert['status']} · {'Active detection' if alert['active'] else 'Superseded — retained history'}")
        if alert["incident_ids"]:
            st.text(f"Associated incidents: {alert['incident_ids']}")
    quick_a, quick_b, quick_c = st.columns(3)
    if quick_a.button("Mark as Investigating", key=f"{key_prefix}_investigate", use_container_width=True):
        services.alerts.update_status(alert_id, "Investigating", "Analyst started investigation")
        st.toast("Alert moved to Investigating")
        st.rerun()
    if quick_b.button("Mark as False Positive", key=f"{key_prefix}_false_positive", use_container_width=True):
        st.session_state[f"{key_prefix}_confirm_false_positive"] = True
    def create_incident() -> None:
        st.session_state["incident_alert_ids"] = [alert_id]
        navigate_to("Incident Investigation")
    quick_c.button("Create incident", key=f"{key_prefix}_create_incident", use_container_width=True)
    if st.session_state.get(f"{key_prefix}_confirm_false_positive"):
        with st.container(border=True):
            st.text("Record the legitimate explanation or uncertainty that supports False Positive classification.")
            reason = st.text_area("False-positive reason (required)", max_chars=1000, key=f"{key_prefix}_false_positive_reason")
            if st.button("Confirm False Positive status", key=f"{key_prefix}_confirm_false_positive_action", type="primary"):
                if not reason.strip():
                    st.error("A false-positive reason is required.")
                else:
                    services.alerts.update_status(alert_id, "False Positive", reason)
                    services.alerts.add_note(alert_id, "False-positive considerations", reason)
                    st.session_state[f"{key_prefix}_confirm_false_positive"] = False
                    st.toast("False-positive assessment saved")
                    st.rerun()
    st.text(alert["explanation"])
    with st.container(border=True):
        st.caption("Severity justification")
        st.text(alert["severity_justification"])
    st.json(json.loads(alert["details_json"]), expanded=False)
    evidence_tab, notes_tab, actions_tab, incident_tab = st.tabs(
        ["Supporting events", "Add analyst note", "Recommended actions & status", "Create incident"]
    )
    with evidence_tab:
        render_events(services.alerts.evidence(alert_id), f"{key_prefix}_evidence")
        st.caption("Timeline evidence is re-sorted by stored UTC timestamp and event ID, independent of ingestion order.")
        _related_leads(services, alert)
    with notes_tab:
        notes = services.alerts.notes(alert_id)
        if not notes:
            st.info("No alert notes have been recorded.")
        for note in notes:
            with st.container(border=True):
                st.text(f"{note['category']} · {note['author']} · {note['created_at']}")
                st.text(note["note"])
        with st.form(f"{key_prefix}_note"):
            category = st.selectbox("Note category", ["Initial observations", "Supporting evidence", "Possible explanations", "False-positive considerations", "Risk assessment", "Recommended response", "Final conclusion"])
            note = st.text_area("Analyst note", max_chars=20_000, placeholder="Record observations, alternate explanations, uncertainty, and next checks.")
            author = st.text_input("Analyst", value=services.settings.get("analyst_name", "Analyst"), max_chars=200)
            if st.form_submit_button("Save note", use_container_width=True):
                try:
                    services.alerts.add_note(alert_id, category, note, author)
                    st.success("Investigation note saved.")
                except ValueError as error:
                    st.error(str(error))
    with actions_tab:
        rule = services.rules.get(alert["rule_id"])
        for action in rule.recommended_actions:
            st.text(f"• {action}")
        st.caption("Recommendations require authorised human review. No containment is performed by SentinelLite.")
        with st.form(f"{key_prefix}_status"):
            status = st.selectbox("Alert status", ALERT_STATUSES, index=ALERT_STATUSES.index(alert["status"]))
            note = st.text_input("Status rationale (optional)", max_chars=500)
            if st.form_submit_button("Update alert status", use_container_width=True):
                try:
                    services.alerts.update_status(alert_id, status, note)
                    st.success("Alert status saved.")
                except ValueError as error:
                    st.error(str(error))
    with incident_tab:
        suggestions = services.incidents.suggestions(alert_id)
        if suggestions:
            st.dataframe(pd.DataFrame(suggestions), use_container_width=True, hide_index=True)
            st.caption("Suggestions require at least two shared entities and temporal proximity. Nothing is merged automatically.")
        else:
            st.info("No explainable multi-entity correlation suggestions were found.")
        all_alerts = services.alerts.list(active_only=False)
        options = [item["alert_id"] for item in all_alerts]
        with st.form(f"{key_prefix}_incident"):
            selected = st.multiselect("Alerts to group explicitly", options, default=[alert_id])
            title = st.text_input("Incident title", value=f"Investigation — {alert['detection_name']}", max_chars=300)
            description = st.text_area("Incident description", value="Review the linked detections, supporting events, alternate explanations, and affected entities.", max_chars=20_000)
            severity = st.selectbox("Incident severity", SEVERITIES, index=SEVERITIES.index(alert["severity"]))
            if st.form_submit_button("Create incident", type="primary", use_container_width=True):
                try:
                    incident_id = services.incidents.create(title, description, severity, selected)
                    st.session_state["active_incident_id"] = incident_id
                    st.success(f"Created {incident_id}. Open Incident Investigation to continue.")
                except ValueError as error:
                    st.error(str(error))
