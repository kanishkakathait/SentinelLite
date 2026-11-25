from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import SAMPLE_GROUND_TRUTH_FILE
from detection.evaluation import evaluate_detections, load_ground_truth
from pages.common import SEVERITY_COLOURS, page_header, render_events, semantic_table_styles, style_chart

CHART_CONFIG = {"displaylogo": False, "responsive": True}


def render(services) -> None:
    page_header("Threat detection", "Inspect real detection coverage, rule configuration, and explicit synthetic evaluation without assuming alert truth.", eyebrow="Monitoring / Detection coverage")
    st.info("Reprocessing sorts events by UTC timestamp, recomputes non-overlapping episodes, refreshes matching evidence, and preserves analyst work. Superseded findings remain inactive history.")
    if st.button("Run detection on all stored events", type="primary", use_container_width=True):
        with st.spinner("Evaluating all stored detection episodes…"):
            result = services.detection.run()
        st.session_state["threat_detection_run"] = result
    result = st.session_state.get("threat_detection_run")
    if result:
        columns = st.columns(5)
        for column, (label, value) in zip(columns, [("Findings", result.findings), ("Created", result.created), ("Refreshed", result.refreshed), ("Superseded", result.superseded), ("Active", result.active)]):
            column.metric(label, value)
        st.success("Detection is synced with the full stored event set. Existing incidents, notes, and analyst statuses were preserved.")
    alerts = services.alerts.list()
    rules = services.rules.list()
    table_rows = []
    for rule in rules:
        matches = [item for item in alerts if item["rule_id"] == rule.rule_id]
        table_rows.append({
            "detection_name": rule.name, "active_alerts": len(matches), "severity": rule.severity,
            "rule_status": "Enabled" if rule.enabled else "Disabled", "last_detection": max((item["alert_timestamp"] for item in matches), default="No active detection"),
        })
    detect_frame = pd.DataFrame(table_rows)
    st.subheader("Detection coverage")
    st.caption("Active alerts are represented as horizontal bars so long detection names remain readable.")
    figure = px.bar(detect_frame, x="active_alerts", y="detection_name", orientation="h", color="severity", color_discrete_map=SEVERITY_COLOURS, labels={"active_alerts": "Active alerts", "detection_name": "Detection rule", "severity": "Severity"}, hover_data={"last_detection": True, "rule_status": True})
    figure.update_layout(height=max(300, len(rules) * 72), yaxis={"categoryorder": "total ascending"}, xaxis={"title": "Active alerts"})
    st.plotly_chart(style_chart(figure), use_container_width=True, config=CHART_CONFIG)
    st.dataframe(semantic_table_styles(detect_frame), use_container_width=True, hide_index=True, column_config={"detection_name": "Detection rule", "active_alerts": "Active alerts", "rule_status": "Rule status", "last_detection": "Last detection (UTC)"})
    st.divider()
    st.subheader("Inspect a rule")
    by_id = {rule.rule_id: rule for rule in rules}
    selected = st.selectbox("Detection rule", list(by_id), key="threat_detection_rule_inspection")
    rule = by_id[selected]
    st.text(f"{rule.name} · {rule.severity} · {'Enabled' if rule.enabled else 'Disabled'}")
    st.text(rule.description)
    st.caption("Configuration and relevant event fields")
    st.json(rule.config, expanded=True)
    st.caption(rule.documentation)
    rule_alerts = [item for item in alerts if item["rule_id"] == selected]
    if rule_alerts:
        latest = rule_alerts[0]
        st.text(f"Latest active example: {latest['alert_id']} · {latest['alert_timestamp']}")
        st.text(latest["explanation"])
        render_events(services.alerts.evidence(latest["alert_id"]), f"threat_rule_{selected}")
    else:
        st.info("No active alert examples exist for this rule. Refine the detection range or run an isolated sample in Detection Rules.")
    st.divider()
    st.subheader("Synthetic scenario evaluation")
    st.caption("Evaluation units are expected (scenario_id, rule_id) pairs. Supporting event IDs attribute alerts to scenarios; repeated episodes do not inflate true positives. This is not real-world accuracy evidence.")
    uploaded_truth = st.file_uploader("Optional custom ground-truth CSV", type=["csv"], help="Columns: event_id, scenario_id, scenario_label, expected_rules (pipe-separated). Supports the matching labelled event set, not arbitrary uploads.")
    if st.button("Evaluate active findings", use_container_width=True):
        try:
            truth = load_ground_truth(uploaded_truth.getvalue().decode("utf-8")) if uploaded_truth else load_ground_truth(SAMPLE_GROUND_TRUTH_FILE)
            st.session_state["evaluation_result"] = evaluate_detections(services.database, truth)
        except (ValueError, UnicodeDecodeError) as error:
            st.error(str(error))
    evaluation = st.session_state.get("evaluation_result")
    if evaluation:
        columns = st.columns(6)
        values = [("True positives", evaluation.true_positives), ("False positives", evaluation.false_positives), ("False negatives", evaluation.false_negatives), ("Precision", f"{evaluation.precision:.1%}"), ("Recall", f"{evaluation.recall:.1%}"), ("Duplicate matches", evaluation.duplicate_matches)]
        for column, (label, value) in zip(columns, values):
            column.metric(label, value)
        if evaluation.false_positive_pairs:
            with st.expander("False-positive matches"):
                st.dataframe(pd.DataFrame(evaluation.false_positive_pairs), use_container_width=True, hide_index=True)
        if evaluation.false_negative_pairs:
            with st.expander("False-negative matches"):
                st.dataframe(pd.DataFrame(evaluation.false_negative_pairs), use_container_width=True, hide_index=True)
        if not evaluation.true_positive_pairs:
            st.warning("No expected scenario-rule matches were found. Ensure logs and ground truth belong to the same dataset and detection has run.")
    with st.expander("Implementation safeguards"):
        st.markdown("- Missing IPs or usernames cannot satisfy entity-correlation rules.\n- Repeated ingestion yields identical event hashes; repeat detection refreshes alert IDs.\n- Off-hours checks use configured IANA timezones; persistence uses fixed-width UTC.\n- Privileged or off-hours matches are contextual and are never proof of compromise.\n- Older results are inactive, not deleted, when recomputation no longer reproduces them.")
