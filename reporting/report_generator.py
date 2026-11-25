from __future__ import annotations

import html
import json
from typing import Any

from core.database import Database
from investigations.incident_manager import IncidentManager
from investigations.timeline import incident_timeline


def markdown_text(value: Any) -> str:
    text = " ".join(str(value if value is not None else "Not recorded").splitlines())
    text = html.escape(text, quote=False)
    punctuation = "\\`*_{}[]()#+-.!|>~-"
    return "".join(f"\\{character}" if character in punctuation else character for character in text)


def html_text(value: Any) -> str:
    return html.escape(str(value if value is not None else "Not recorded"))


def incident_report_data(database: Database, incident_id: str) -> dict[str, Any]:
    manager = IncidentManager(database)
    incident = manager.get(incident_id)
    alert_rows = [dict(row) for row in database.fetch_all(
        """
        SELECT a.* FROM incident_alerts ia JOIN security_alerts a ON a.alert_id = ia.alert_id
        WHERE ia.incident_id = ? ORDER BY a.alert_timestamp, a.alert_id
        """, (incident_id,),
    )]
    recommendations = []
    false_positive_context = []
    for rule_id in sorted({alert["rule_id"] for alert in alert_rows}):
        rule = database.fetch_one("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))
        if rule:
            recommendations.extend(json.loads(rule["recommended_actions_json"]))
            false_positive_context.append(f"{rule['name']}: {rule['documentation']}")
    evidence_by_alert: dict[str, list[dict[str, Any]]] = {}
    for alert in alert_rows:
        evidence_by_alert[alert["alert_id"]] = [dict(row) for row in database.fetch_all(
            """
            SELECT e.* FROM security_events e JOIN alert_events ae ON ae.event_id = e.event_id
            WHERE ae.alert_id = ? ORDER BY e.event_timestamp, e.event_id
            """, (alert["alert_id"],),
        )]
    evidence_rows = [event for events in evidence_by_alert.values() for event in events]
    simulated_state = "No supporting event labels" if not evidence_rows else "Synthetic only" if all(event["simulated"] for event in evidence_rows) else "Public/manual only" if not any(event["simulated"] for event in evidence_rows) else "Mixed synthetic and public/manual"
    return {
        "incident": incident, "alerts": alert_rows, "notes": manager.notes(incident_id),
        "timeline": incident_timeline(database, incident_id), "evidence_by_alert": evidence_by_alert,
        "evidence_mode": simulated_state,
        "recommendations": list(dict.fromkeys(recommendations)),
        "false_positive_context": false_positive_context,
    }


def current_conclusion(incident: dict[str, Any]) -> str:
    if incident["status"] in {"Resolved", "Closed"} and incident["resolution_summary"]:
        return incident["resolution_summary"]
    return "The investigation is not recorded as resolved; no final compromise determination is asserted."


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(markdown_text(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def html_table(headers: list[str], rows: list[list[Any]]) -> str:
    header = "".join(f"<th>{html_text(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{html_text(value)}</td>" for value in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>'


def render_markdown(database: Database, incident_id: str, data: dict[str, Any] | None = None) -> str:
    data = data if data is not None else incident_report_data(database, incident_id)
    incident = data["incident"]
    users = json.loads(incident["affected_users_json"])
    hosts = json.loads(incident["affected_hosts_json"])
    source_ips = json.loads(incident["source_ips_json"])
    overview_rows = [
        ("Incident ID", incident_id), ("Status", incident["status"]), ("Severity", incident["severity"]),
        ("Created", incident["created_at"]), ("Last updated", incident["updated_at"]),
        ("Resolved at", incident["resolved_at"] or "Active / not recorded"), ("Affected accounts", ", ".join(users) or "Not supplied"),
        ("Affected systems", ", ".join(hosts) or "Not supplied"), ("Source IP addresses", ", ".join(source_ips) or "Not supplied"),
        ("Evidence origin", data["evidence_mode"]),
    ]
    lines = [
        "# SentinelLite — Security Incident Report",
        f"## {markdown_text(incident['title'])}",
        f"**{markdown_text(incident_id)}**",
        "",
        "> **SentinelLite / Security Operations & Incident Response**  ",
        "> Educational security operations report generated only from persisted local records. No automatic containment is claimed.",
        "",
        "## 1. Executive Summary", "",
        markdown_text(incident["description"]), "",
        f"**Current status:** {markdown_text(incident['status'])}  ",
        f"**Recorded severity:** {markdown_text(incident['severity'])}  ", "",
        markdown_text(current_conclusion(incident)), "",
        "## 2. Incident Overview", "", markdown_table(["Attribute", "Record"], overview_rows), "",
        "## 3. Detection Details", "",
    ]
    if not data["alerts"]:
        lines.append("No linked detections have been recorded for this incident.")
    for alert in data["alerts"]:
        lines.extend([
            f"### {markdown_text(alert['detection_name'])}", "",
            markdown_table(
                ["Field", "Value"], [
                    ("Alert ID", alert["alert_id"]), ("Rule", alert["rule_id"]),
                    ("Detection timestamp (UTC)", alert["alert_timestamp"]), ("Severity", alert["severity"]),
                    ("Alert status", alert["status"]), ("Current detection state", "Active" if alert["active"] else "Superseded history"),
                ],
            ), "",
            markdown_text(alert["explanation"]), "",
            f"**Severity rationale:** {markdown_text(alert['severity_justification'])}", "",
        ])
    lines.extend(["## 4. Chronological Timeline", "", markdown_table(["Exact UTC timestamp", "Activity marker", "Record", "Evidence reference"], [(entry["timestamp"], entry.get("marker", "event"), f"{entry['type']} — {entry['title']} — {entry['detail']}", entry["reference"]) for entry in data["timeline"]]), "", "## 5. Supporting Evidence", ""])
    for alert_id, events in data["evidence_by_alert"].items():
        lines.extend([f"### Linked alert: {markdown_text(alert_id)}", ""])
        if not events:
            lines.append("No supporting event rows are available.")
        lines.append(markdown_table(
            ["Exact UTC timestamp", "Event ID", "Result / user / host / source", "Raw log evidence"],
            [(
                event["event_timestamp"], event["event_id"],
                f"{event['authentication_result'] or 'No result'} / {event['username'] or 'Not supplied'} / {event['hostname'] or 'Not supplied'} / {event['source_ip'] or 'Not supplied'}",
                event["raw_message"],
            ) for event in events],
        ))
        lines.append("")
    lines.extend(["## 6. Analyst Findings", ""])
    if not data["notes"]:
        lines.append("No analyst findings have been recorded. No inference has been inserted in place of investigation notes.")
    for note in data["notes"]:
        edited = f"; last edit {note['last_edited_at']}" if note.get("last_edited_at") else ""
        lines.append(f"- **{markdown_text(note['category'])} ({markdown_text(note['created_at'])}{markdown_text(edited)}, {markdown_text(note['author'])}):** {markdown_text(note['note'])}")
    lines.extend(["", "## 7. Recommended Actions", ""])
    actions = ([incident["recommended_actions"]] if incident["recommended_actions"] else []) + data["recommendations"]
    if not actions:
        lines.append("- No response action has been recorded. Review scope and follow authorised organisational procedures.")
    lines.extend(f"- {markdown_text(action)}" for action in actions)
    lines.extend([
        "", "Response entries are recommendations/findings only. SentinelLite does not block sources, reset credentials, isolate systems, or change devices automatically.", "",
        "## 8. Incident Status", "",
        f"- **Current workflow state:** {markdown_text(incident['status'])}",
        f"- **Resolution record:** {markdown_text(incident['resolution_summary'] if incident['status'] in {'Resolved', 'Closed'} and incident['resolution_summary'] else 'No active resolution summary; the investigation is ongoing or reopened.')}",
        f"- **Resolution timestamp (UTC):** {markdown_text(incident['resolved_at'] or 'Not resolved')}",
        f"- **Risk context:** {len(users)} accounts, {len(hosts)} systems, and {len(source_ips)} source IP addresses in the evidence-linked incident scope. Recorded severity is {markdown_text(incident['severity'])}; this is not a likelihood or confirmed-damage estimate.",
        f"- **Recorded last update:** {markdown_text(incident['updated_at'])}", "",
        "## 9. Limitations and Uncertainties", "",
        "Evidence completeness depends on the supplied logs, source coverage, timestamp reliability, and source trustworthiness. Detection and severity are investigation aids, not a determination of compromise, impact, or attribution. Every recommendation requires authorised human review.", "",
        "### False-positive and alternate explanations", "",
    ])
    lines.extend(f"- {markdown_text(context)}" for context in data["false_positive_context"])
    lines.extend(f"- Analyst assessment: {markdown_text(note['note'])}" for note in data["notes"] if note["category"] == "False-positive considerations")
    lines.extend(["", "### Recorded outcome", "", markdown_text(current_conclusion(incident)), "", "---", "**SentinelLite** · Lightweight security monitoring and investigation · Local educational application · Not a production SIEM, EDR, or automatic incident containment service."])
    return "\n".join(lines) + "\n"


REPORT_STYLES = """
:root{color-scheme:light;--ink:#15273e;--muted:#52647b;--line:#d5dfeb;--accent:#087fa5}*{box-sizing:border-box}body{font:15px/1.6 Inter,Arial,Helvetica,sans-serif;max-width:1320px;margin:0;background:#f4f7fb;color:var(--ink)}main{padding:24px 34px 42px;margin:0 auto}.brand{padding:0 0 21px;border-bottom:3px solid #1697c2;letter-spacing:.06em;font-size:12px;color:#3b708d;font-weight:700}.brand-name{font-size:28px;letter-spacing:-.04em;color:#103451;margin-bottom:6px}h1{line-height:1.18;max-width:1050px;margin:27px 0 10px;font-size:32px;letter-spacing:-.03em}h2{font-size:20px;line-height:1.3;border-bottom:1px solid var(--line);padding-bottom:9px;margin:30px 0 15px}h3{font-size:16px;color:#284d70}section{margin:20px 0 25px}.subtitle{color:var(--muted);max-width:1040px;margin-top:0}.badge{display:inline-block;padding:4px 9px;border-radius:7px;color:white;background:#38526e;font-size:12px;font-weight:600;text-transform:capitalize}.badge.critical{background:#af3644}.badge.high{background:#ba652e}.badge.medium{background:#8a6b20}.badge.low{background:#247896}.badge.informational{background:#5b6e85}.summary-card{background:white;border:1px solid var(--line);border-radius:10px;padding:14px 18px;box-shadow:0 2px 8px rgba(22,48,73,.045)}.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--line);background:white}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid #e7edf4;vertical-align:top}th{background:#eaeff5;color:#25415f;font-size:12px;letter-spacing:.035em}td:first-child{font-weight:500;min-width:105px}tr:last-child td{border-bottom:0}.evidence{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-word;white-space:pre-wrap}.notice{border-left:4px solid #2c9bbd;background:#eaf4f8;border-radius:5px;padding:12px 16px;margin:16px 0}.footer{margin-top:32px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12px}li{margin:7px 0}@media(max-width:700px){main{padding:16px}h1{font-size:27px}table{font-size:12px}}@media print{body{background:white}main{padding:0;max-width:none}section{break-inside:avoid}.brand{print-color-adjust:exact}.no-print{display:none}}
"""


def paragraph(value: Any, css_class: str = "") -> str:
    return f'<p class="{css_class}">{html_text(value)}</p>'


def render_html(database: Database, incident_id: str, data: dict[str, Any] | None = None) -> str:
    data = data if data is not None else incident_report_data(database, incident_id)
    incident = data["incident"]
    severity_class = incident["severity"] if incident["severity"] in {"critical", "high", "medium", "low", "informational"} else "informational"
    sections = []
    summary = f"{incident['description']} Current status: {incident['status']}. {current_conclusion(incident)}"
    sections.append(f"<section><h2>1. Executive Summary</h2><div class=\"summary-card\">{paragraph(summary)}</div></section>")
    overview = [
        ("Incident ID", incident_id), ("Severity", incident["severity"]), ("Status", incident["status"]),
        ("Created / updated", f"{incident['created_at']} / {incident['updated_at']}"),
        ("Resolved at", incident["resolved_at"] or "Not resolved"),
        ("Affected accounts", ", ".join(json.loads(incident["affected_users_json"])) or "Not supplied"),
        ("Affected systems", ", ".join(json.loads(incident["affected_hosts_json"])) or "Not supplied"),
        ("Source IP addresses", ", ".join(json.loads(incident["source_ips_json"])) or "Not supplied"),
        ("Evidence origin", data["evidence_mode"]),
    ]
    sections.append("<section><h2>2. Incident Overview</h2>" + html_table(["Attribute", "Record"], overview) + "</section>")
    detection_details = []
    for alert in data["alerts"]:
        details = [
            ("Alert ID", alert["alert_id"]), ("Rule", alert["rule_id"]),
            ("Timestamp (UTC)", alert["alert_timestamp"]), ("Severity", alert["severity"]),
            ("Status", alert["status"]), ("Current state", "Active" if alert["active"] else "Superseded history"),
        ]
        detection_details.append("<article><h3>" + html_text(alert["detection_name"]) + "</h3>" + html_table(["Attribute", "Value"], details) + paragraph(alert["explanation"]) + "<p><strong>Severity rationale:</strong> " + html_text(alert["severity_justification"]) + "</p></article>")
    sections.append("<section><h2>3. Detection Details</h2>" + ("".join(detection_details) or paragraph("No linked detections have been recorded.")) + "</section>")
    timeline = [(entry["timestamp"], entry.get("marker", "event"), f"{entry['type']} — {entry['title']}", entry["detail"], entry["reference"]) for entry in data["timeline"]]
    sections.append("<section><h2>4. Chronological Timeline</h2>" + html_table(["Exact UTC timestamp", "Marker", "Activity", "Evidence", "Reference"], timeline) + "</section>")
    evidence_sections = []
    for alert_id, events in data["evidence_by_alert"].items():
        rows = [(
            event["event_timestamp"], event["event_id"], event["authentication_result"] or "No result",
            event["username"] or "Not supplied", event["hostname"] or "Not supplied", event["source_ip"] or "Not supplied", event["raw_message"],
        ) for event in events]
        evidence_sections.append("<h3>Linked alert: " + html_text(alert_id) + "</h3>" + html_table(["Timestamp (UTC)", "Event ID", "Result", "Account", "Host", "Source IP", "Raw log evidence"], rows))
    sections.append("<section><h2>5. Supporting Evidence</h2>" + ("".join(evidence_sections) if evidence_sections else paragraph("No supporting event rows are linked to this incident.")) + "</section>")
    notes = data["notes"]
    analyst_notes = "".join(
        "<article><h3>" + html_text(note["category"]) + "</h3>"
        + paragraph(f"Author: {note['author']} · Created: {note['created_at']}" + (f" · Last edited: {note['last_edited_at']}" if note.get("last_edited_at") else ""), "subtitle")
        + paragraph(note["note"]) + "</article>" for note in notes
    )
    sections.append("<section><h2>6. Analyst Findings</h2>" + (analyst_notes or paragraph("No analyst findings have been recorded.")) + "</section>")
    actions = ([incident["recommended_actions"]] if incident["recommended_actions"] else []) + data["recommendations"]
    action_list = "".join(f"<li>{html_text(action)}</li>" for action in actions)
    sections.append("<section><h2>7. Recommended Actions</h2><ul>" + action_list + "</ul><div class=\"notice\">These are recommendations only. SentinelLite does not block sources, reset credentials, isolate hosts, or alter devices automatically.</div></section>")
    users = json.loads(incident["affected_users_json"])
    hosts = json.loads(incident["affected_hosts_json"])
    ips = json.loads(incident["source_ips_json"])
    status_rows = [
        ("Workflow status", incident["status"]),
        ("Resolution summary", incident["resolution_summary"] if incident["status"] in {"Resolved", "Closed"} and incident["resolution_summary"] else "Ongoing or reopened; no active final resolution summary."),
        ("Resolution timestamp (UTC)", incident["resolved_at"] or "Not resolved"),
        ("Scope recorded", f"{len(users)} accounts · {len(hosts)} systems · {len(ips)} source IP addresses"),
        ("Recorded severity", incident["severity"]),
        ("Last persistent update", incident["updated_at"]),
    ]
    sections.append("<section><h2>8. Incident Status</h2>" + html_table(["Attribute", "Record"], status_rows) + "</section>")
    limitations = [
        "Evidence completeness depends on log coverage, source reliability, timestamp accuracy, and fields supplied by the source. Limited evidence may not establish scope, intent, likelihood, impact, or attribution.",
        "The recorded severity supports triage but is not an official CVSS score, exploitability probability, or proof of compromise.",
        "No automatic isolation, password reset, IP block, or other containment is inferred from a status change. Response requires authorised human review.",
    ]
    limitations.extend(data["false_positive_context"])
    limitations.extend(f"Analyst: {note['note']}" for note in notes if note["category"] == "False-positive considerations")
    limitations.append(current_conclusion(incident))
    sections.append("<section><h2>9. Limitations and Uncertainties</h2><ul>" + "".join(f"<li>{html_text(item)}</li>" for item in limitations) + "</ul></section>")
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelLite Incident Report</title><style>{REPORT_STYLES}</style></head><body><main><header class="brand"><div class="brand-name">SentinelLite</div>SECURITY OPERATIONS &amp; INCIDENT RESPONSE</header><h1>{html_text(incident["title"])}</h1><p class="subtitle">Security Incident Report · {html_text(incident_id)} · <span class="badge {severity_class}">{html_text(incident["severity"])}</span></p><div class="notice">Educational security operations report generated exclusively from persisted incident, detection, evidence, analyst-note, and status-history records. No final conclusion is inferred beyond the investigation data shown below.</div>' + "".join(sections) + '<footer class="footer"><strong>SentinelLite</strong> · Lightweight local educational monitoring and investigation. Not a production SIEM, EDR, vulnerability scanner, or automatic incident containment platform.</footer></main></body></html>\n'
