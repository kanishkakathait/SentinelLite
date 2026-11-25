from __future__ import annotations

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import INCIDENT_STATUSES, SEVERITIES
from core.time_utils import to_storage, utc_now
from pages.common import SEVERITY_COLOURS, metric_card, page_header, render_alert_workspace, render_activity_feed, section_heading, semantic_table_styles, short_id, style_chart

CHART_CONFIG = {"displaylogo": False, "responsive": True, "modeBarButtonsToRemove": ["lasso2d", "select2d"]}


def empty_chart(message: str) -> None:
    st.info(message)


def render_events_by_source(services, options: list[str]) -> None:
    if not options:
        return
    with st.expander("Inspect related events by source IP"):
        selected_ip = st.selectbox("Source IP", options, key="overview_source_inspection")
        records = services.events.search(source_ip=selected_ip, limit=15)
        rows = [{
            "timestamp": row["event_timestamp"], "result": row["authentication_result"],
            "account": row["username"], "host": row["hostname"], "event_id": row["event_id"],
        } for row in records]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        event_id = st.selectbox("Evidence event ID", [row["event_id"] for row in rows], key="overview_event_selection")
        event = next(row for row in records if row["event_id"] == event_id)
        st.text(f"{event['event_timestamp']} · {event['username'] or 'No account supplied'} · {event['hostname'] or 'No host supplied'}")
        st.code(event["raw_message"], language="text", wrap_lines=True)


def render(services) -> None:
    page_header("Security operations centre", "A live operating picture built entirely from persisted events, detections, and investigation records.", eyebrow="SentinelLite / Command centre")
    summary = services.metrics.summary()
    cards = [
        ("total_events", "▤", "Total Security Events", f"{summary['total_events']:,}", "All normalised stored events", "neutral", "Security Events"),
        ("events_today", "◔", "Processed Today", f"{summary['events_today']:,}", "Ingested during the local day", "neutral", "Security Events"),
        ("open_alerts", "⚠", "Open Security Alerts", f"{summary['open_alerts']:,}", "Active alerts: New / Investigating", "warning" if summary["open_alerts"] else "success", "Security Alerts"),
        ("priority_alerts", "△", "Critical & High Alerts", f"{summary['critical_high_alerts']:,}", "High-priority active detections", "danger" if summary["critical_high_alerts"] else "success", "Security Alerts"),
        ("suspicious_ips", "⌘", "Suspicious Source IPs", f"{summary['suspicious_ips']:,}", "Distinct sources on active alerts", "warning" if summary["suspicious_ips"] else "neutral", "Threat Detection"),
        ("open_incidents", "▣", "Open Incidents", f"{summary['open_incidents']:,}", "Open, Investigating, or Contained", "warning" if summary["open_incidents"] else "success", "Incident Investigation"),
        ("resolved_incidents", "✓", "Resolved Incidents", f"{summary['resolved_incidents']:,}", "Persisted resolved / closed cases", "success", "Incident Investigation"),
        ("mean_resolution", "◷", "Average Resolution Time", "Not enough data" if summary["mean_resolution_hours"] is None else f"{summary['mean_resolution_hours']:.1f} h", "Created to first recorded resolution", "neutral", "Incident Investigation"),
    ]
    for index in range(0, len(cards), 4):
        for column, arguments in zip(st.columns(4), cards[index:index + 4]):
            with column:
                metric_card(*arguments)
    zone = ZoneInfo(services.settings.get("timezone", "Australia/Melbourne"))
    now = utc_now().astimezone(zone)
    controls = st.columns([2, 1])
    with controls[0]:
        period = st.selectbox("Analysis window", ["Last hour", "Last 24 hours", "Last 7 days", "Custom date range"], index=1)
    if period == "Custom date range":
        dates = controls[1].date_input("Local date range", value=((now - timedelta(days=7)).date(), now.date()), max_value=now.date())
        if not isinstance(dates, tuple) or len(dates) != 2:
            st.info("Select both dates to calculate the custom window.")
            return
        start = datetime.combine(dates[0], time.min, tzinfo=zone)
        end = datetime.combine(dates[1] + timedelta(days=1), time.min, tzinfo=zone)
    else:
        delta = {"Last hour": timedelta(hours=1), "Last 24 hours": timedelta(hours=24), "Last 7 days": timedelta(days=7)}[period]
        start, end = now - delta, now
    events = services.metrics.events_in_range(start, end)
    alerts = services.metrics.alerts_in_range(start, end)
    event_frame = pd.DataFrame(events)
    alert_frame = pd.DataFrame(alerts)
    available_categories = ["All"] + sorted({item["event_category"] for item in events if item["event_category"]})
    with controls[1]:
        category = st.selectbox("Timeline event category", available_categories)
    filtered_events = event_frame if category == "All" else event_frame[event_frame["event_category"] == category]
    st.divider()
    chart_left, chart_right = st.columns([2, 1])
    with chart_left:
        section_heading("Security events over time", f"Occurrence timestamps · {zone.key}", "⌁")
        if filtered_events.empty:
            empty_chart("No events match this time and category filter.")
        else:
            frame = filtered_events.copy()
            frame["timestamp"] = pd.to_datetime(frame["event_timestamp"], utc=True, format="ISO8601").dt.tz_convert(zone)
            frequency = "5min" if period == "Last hour" else "1h" if period == "Last 24 hours" else "1D"
            volume = frame.set_index("timestamp").resample(frequency).size().rename("events").reset_index()
            figure = px.area(volume, x="timestamp", y="events", markers=True, color_discrete_sequence=["#56C3EA"], labels={"timestamp": "Time", "events": "Events"})
            figure.update_traces(line={"width": 2}, fillcolor="rgba(54,170,221,.12)", hovertemplate="Time %{x}<br>Events %{y}<extra></extra>", marker={"size": 5})
            figure.update_layout(height=335)
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    with chart_right:
        section_heading("Alert severity", "Active in analysis window", "⚠")
        if alert_frame.empty:
            empty_chart("No active alerts in this window.")
        else:
            counts = alert_frame.groupby("severity").size().reindex(SEVERITIES, fill_value=0).rename("alerts").reset_index()
            counts["severity"] = counts["severity"].str.title()
            figure = px.pie(counts, values="alerts", names="severity", color="severity", color_discrete_map={name.title(): colour for name, colour in SEVERITY_COLOURS.items()}, hole=.6)
            figure.update_traces(textinfo="label+value", hovertemplate="%{label}<br>%{value} alerts<extra></extra>")
            figure.update_layout(height=335, legend={"orientation": "h", "y": -0.08})
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    activity, sources = st.columns(2)
    with activity:
        section_heading("Authentication activity", f"{period} · stored results", "◔")
        if event_frame.empty:
            empty_chart("No authentication activity in this window.")
        else:
            auth = event_frame[event_frame["event_category"] == "authentication"]
            suspicious = services.database.fetch_one(
                """SELECT COUNT(DISTINCT e.event_id) AS count FROM security_events e
                   JOIN alert_events ae ON ae.event_id = e.event_id
                   JOIN security_alerts a ON a.alert_id = ae.alert_id
                   WHERE a.active = 1 AND e.event_category = 'authentication'
                     AND e.event_timestamp >= ? AND e.event_timestamp < ?""",
                (to_storage(start), to_storage(end)),
            )["count"]
            bars = pd.DataFrame({"activity": ["Successful logins", "Failed logins", "Alert-linked auth"], "events": [int((auth["authentication_result"] == "success").sum()), int((auth["authentication_result"] == "failure").sum()), suspicious]})
            figure = px.bar(bars, x="activity", y="events", color="activity", color_discrete_map={"Successful logins": "#4FD1AA", "Failed logins": "#F28B91", "Alert-linked auth": "#F3B766"}, labels={"activity": "Activity", "events": "Events"})
            figure.update_layout(showlegend=False, height=310, xaxis={"title": ""})
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    with sources:
        section_heading("Top suspicious source IPs", "Associated active alerts", "⌘")
        if alert_frame.empty or alert_frame["source_ip"].dropna().empty:
            empty_chart("No source-IP alert data in this window.")
        else:
            top = alert_frame.dropna(subset=["source_ip"]).groupby("source_ip").size().nlargest(8).rename("alerts").reset_index()
            figure = px.bar(top, x="alerts", y="source_ip", orientation="h", color_discrete_sequence=["#F4A266"], labels={"alerts": "Active alerts", "source_ip": "Source IP"}, hover_data={"source_ip": False})
            figure.update_layout(height=310, yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    render_events_by_source(services, list(alert_frame["source_ip"].dropna().unique()) if not alert_frame.empty else [])
    breakdown, incident_chart = st.columns(2)
    with breakdown:
        section_heading("Threat detection breakdown", "Active alerts by rule", "△")
        if alert_frame.empty:
            empty_chart("No active detections in this range.")
        else:
            rule_counts = alert_frame.groupby(["detection_name", "severity"]).size().rename("alerts").reset_index()
            figure = px.bar(rule_counts, x="alerts", y="detection_name", orientation="h", color="severity", color_discrete_map=SEVERITY_COLOURS, labels={"alerts": "Active alerts", "detection_name": "Detection rule"})
            figure.update_layout(height=340, yaxis={"categoryorder": "total ascending"}, xaxis={"title": "Active alerts"})
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    with incident_chart:
        section_heading("Incident status distribution", "All persistent incidents", "◎")
        incident_rows = services.database.fetch_all("SELECT status, COUNT(*) AS count FROM incidents GROUP BY status")
        if not incident_rows:
            empty_chart("No incidents have been created yet.")
        else:
            counts = pd.DataFrame([dict(row) for row in incident_rows]).set_index("status").reindex(INCIDENT_STATUSES, fill_value=0).reset_index()
            figure = px.bar(counts, x="count", y="status", orientation="h", color="status", color_discrete_map={"Open": "#A2B3C7", "Investigating": "#B4A0FC", "Contained": "#67E8F9", "Resolved": "#73DFBD", "Closed": "#B5BDCB"}, labels={"count": "Incidents", "status": "Status"})
            figure.update_layout(showlegend=False, height=340, yaxis={"categoryorder": "array", "categoryarray": list(reversed(INCIDENT_STATUSES))})
            st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    section_heading("Recent security alerts", "All active alerts · newest first", "⚠")
    recent = services.alerts.list()[:50]
    if not recent:
        st.info("No active alerts are available. Run detection after ingestion or enable Demo Mode.")
    else:
        display = pd.DataFrame([{
            "id": short_id(item["alert_id"]), "alert_id": item["alert_id"], "detection_rule": item["detection_name"],
            "severity": item["severity"], "timestamp": item["alert_timestamp"], "source_ip": item["source_ip"],
            "affected_user": item["username"], "status": item["status"],
        } for item in recent])
        hidden_id = display.pop("alert_id")
        selected = st.dataframe(semantic_table_styles(display), use_container_width=True, hide_index=True, on_select="rerun", selection_mode="single-row", key="overview_alert_rows", column_config={"id": "Alert ID", "detection_rule": "Detection", "severity": "Severity", "timestamp": "Timestamp", "source_ip": "Source IP", "affected_user": "Affected user", "status": "Status"})
        if selected.selection.rows:
            render_alert_workspace(services, hidden_id.iloc[selected.selection.rows[0]], "overview_alert")
        else:
            st.caption("Select an alert row to open its evidence and investigation workspace.")
    section_heading("Recent security activity", "Latest persisted records · refresh occurs on page reruns", "◷")
    st.caption(f"Read at {now.isoformat(timespec='seconds')}. This feed is not claimed to be continuously live.")
    render_activity_feed(services, limit=8)
