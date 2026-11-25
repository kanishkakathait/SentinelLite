from __future__ import annotations

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

from core.config import ALERT_STATUSES, SEVERITIES
from core.time_utils import from_storage
from core.view_models import paginate, sort_alerts
from pages.common import badge_html, page_header, render_alert_workspace, semantic_table_styles, short_id


def render(services) -> None:
    page_header("Security alerts", "Search, sort, and investigate persisted detections with evidence-led next steps—not automatic attack conclusions.", eyebrow="Monitoring / Alert triage")
    rule_options = {rule.rule_id: rule.name for rule in services.rules.list()}
    first, second, third = st.columns(3)
    severity = first.selectbox("Severity", ["All", *SEVERITIES])
    rule_id = second.selectbox("Detection rule", ["All", *rule_options], format_func=lambda value: value if value == "All" else f"{value} · {rule_options[value]}")
    status = third.selectbox("Status", ["All", *ALERT_STATUSES])
    fourth, fifth = st.columns(2)
    source_ip = fourth.text_input("Source IP", placeholder="Exact source address")
    username = fifth.text_input("Affected account", placeholder="Exact account, including multi-account targets")
    sixth, seventh, eighth = st.columns(3)
    start_date = sixth.date_input("From local date (optional)", value=None, key="alert_start")
    end_date = seventh.date_input("To local date (optional)", value=None, key="alert_end")
    active_only = eighth.checkbox("Active detections only", value=True)
    search = st.text_input("Search alert results", placeholder="Detection name, ID, host, account, or source")
    records = services.alerts.list(
        severity=None if severity == "All" else severity,
        rule_id=None if rule_id == "All" else rule_id,
        status=None if status == "All" else status,
        source_ip=source_ip.strip() or None, username=username.strip() or None,
        active_only=active_only,
    )
    zone = ZoneInfo(services.settings.get("timezone", "Australia/Melbourne"))
    if start_date:
        start = datetime.combine(start_date, time.min, tzinfo=zone)
        records = [item for item in records if from_storage(item["alert_timestamp"]) >= start]
    if end_date:
        end = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=zone)
        records = [item for item in records if from_storage(item["alert_timestamp"]) < end]
    if search.strip():
        needle = search.casefold().strip()
        records = [item for item in records if any(needle in str(item.get(field) or "").casefold() for field in ("alert_id", "detection_name", "hostname", "source_ip", "username", "status"))]
    controls = st.columns([2, 1])
    sort_order = controls[0].selectbox("Sort alerts", ["Newest first", "Oldest first", "Severity, newest first", "Severity, oldest first", "Lowest severity first"])
    page_size = controls[1].selectbox("Rows per page", [10, 25, 50, 100], index=1)
    ordered = sort_alerts(records, sort_order)
    page_items, current_page, total_pages = paginate(ordered, st.session_state.get("alert_page_number", 1), page_size)
    pagination = st.columns([1, 3])
    page_number = pagination[0].number_input("Page", min_value=1, max_value=total_pages, value=current_page, step=1, key="alert_page_number")
    if page_number != current_page:
        page_items, current_page, total_pages = paginate(ordered, page_number, page_size)
    with pagination[1]:
        st.caption(f"{len(records):,} matching alerts · page {current_page} of {total_pages} · sorted and paginated after filtering")
    st.caption("Severity: " + " / ".join(label.title() for label in SEVERITIES))
    legend = st.columns(5)
    for column, label in zip(legend, SEVERITIES):
        with column:
            st.markdown(badge_html(label), unsafe_allow_html=True)
    if not records:
        st.info("No alerts match the selected filters. Change the filters, run detection, or load a synthetic demonstration.")
        return
    if not page_items:
        st.info("No alerts are on this page. Return to page one or change filters.")
        return
    display = pd.DataFrame([{
        "id": short_id(item["alert_id"]), "detection_name": item["detection_name"],
        "severity": item["severity"], "timestamp": item["alert_timestamp"],
        "source_ip": item["source_ip"], "affected_account": item["username"],
        "hostname": item["hostname"], "status": item["status"], "active_state": "Active" if item["active"] else "Superseded",
        "alert_id": item["alert_id"],
    } for item in page_items])
    selected_ids = display.pop("alert_id").tolist()
    selection = st.dataframe(
        semantic_table_styles(display), use_container_width=True, hide_index=True,
        on_select="rerun", selection_mode="single-row", key="alert_management_rows",
        column_config={"id": "Display ID", "detection_name": "Detection", "severity": "Severity", "timestamp": "Detection timestamp (UTC)", "source_ip": "Source IP", "affected_account": "Affected account", "hostname": "Hostname", "status": "Status", "active_state": "Detection state"},
    )
    selected_id = None
    if selection.selection.rows:
        selected_id = selected_ids[selection.selection.rows[0]]
        st.session_state.pop("focused_alert_id", None)
        st.caption(f"Selected alert {selected_id}")
    else:
        focused_id = st.session_state.get("focused_alert_id") or st.query_params.get("alert_id")
        if focused_id:
            selected_id = focused_id
            if not any(item["alert_id"] == selected_id for item in records):
                st.caption("The focused alert is shown outside the current filter set.")
    if selected_id:
        try:
            render_alert_workspace(services, selected_id, "alert_workspace")
        except ValueError:
            st.session_state.pop("focused_alert_id", None)
            st.error("The requested alert no longer exists. Select another persisted alert.")
    else:
        st.caption("Select a result to inspect supporting events, investigation notes, recommended actions, and incidents.")
