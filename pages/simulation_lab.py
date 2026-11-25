from __future__ import annotations

import pandas as pd
import streamlit as st

from pages.common import event_rows, page_header, render_alert_workspace, short_id
from pages.navigation import navigate_to
from simulation.lab import SimulationLab


def open_report(incident_id: str) -> None:
    st.session_state["active_incident_id"] = incident_id
    navigate_to("Security Reports")


def open_incident(incident_id: str) -> None:
    st.session_state["active_incident_id"] = incident_id
    navigate_to("Incident Investigation")


def render_result(services, result) -> None:
    scenario = result.scenario
    st.success(f"Scenario executed at {result.ran_at}. Generated and process steps below correspond to actual service operations on {scenario.label}.")
    with st.container(border=True):
        st.subheader("Step 1 · Generate synthetic authentication events")
        st.text(f"{len(result.events)} generated = {len(result.events)} persisted event identities evaluated; source IPs use reserved documentation ranges.")
        st.caption("Normalised preview. Imported labels remain clearly simulated and never overwrite an event source from the raw log.")
        st.dataframe(pd.DataFrame(event_rows(result.events)), use_container_width=True, hide_index=True)
    with st.container(border=True):
        st.subheader("Step 2 · Process security logs through the real ingestion service")
        counters = st.columns(4)
        counters[0].metric("Received", result.ingestion.received)
        counters[1].metric("Accepted", result.ingestion.accepted)
        counters[2].metric("Exact duplicates", result.ingestion.duplicates)
        counters[3].metric("Rejected", result.ingestion.rejected)
        if result.ingestion.duplicates:
            st.info(f"The replay contains {result.ingestion.duplicates} exact duplicates of previously stored events; these are not counted as new evidence.")
        else:
            st.text("Zero duplicate records were reported for this scenario run.")
    with st.container(border=True):
        st.subheader("Step 3 · Run existing full-store detection")
        counters = st.columns(4)
        counters[0].metric("Computed findings", result.detection.findings)
        counters[1].metric("Created", result.detection.created)
        counters[2].metric("Refreshed", result.detection.refreshed)
        counters[3].metric("Active", result.detection.active)
        st.caption("These counters are for the existing complete event store, not a separate simulation shortcut. Notes, analyst statuses, and incident links are preserved.")
    with st.container(border=True):
        st.subheader("Step 4 · Inspect actual persisted alerts")
        if not result.alerts:
            st.warning("No active alerts match this scenario's evidence under the current rule configuration and enabled state. No alert has been fabricated to satisfy the demonstration.")
            for rule_id in result.scenario.expected_rules:
                rule = services.rules.get(rule_id)
                st.text(f"{rule_id} — {'Enabled' if rule.enabled else 'Disabled'} · Current configuration: {rule.config}")
        else:
            st.text(f"{len(result.alerts)} active alert(s) linked to the generated evidence")
            alert_table = pd.DataFrame([{
                "alert_id": alert["alert_id"], "detection": alert["detection_name"], "severity": alert["severity"],
                "timestamp": alert["alert_timestamp"], "status": alert["status"], "source_ip": alert["source_ip"],
            } for alert in result.alerts])
            st.dataframe(alert_table, use_container_width=True, hide_index=True)
            if len(result.alerts) > 1:
                st.caption("Repeated window episodes may yield multiple alerts for one expected scenario-rule evaluation unit; duplicate matches are counted separately below.")
        st.subheader("Evidence-scoped synthetic evaluation")
        evaluation = result.evaluation
        metrics = st.columns(5)
        metrics[0].metric("Matches (TP)", evaluation.true_positives)
        metrics[1].metric("Unexpected (FP)", evaluation.false_positives)
        metrics[2].metric("Missed (FN)", evaluation.false_negatives)
        metrics[3].metric("Precision", f"{evaluation.precision:.1%}")
        metrics[4].metric("Recall", f"{evaluation.recall:.1%}")
        st.caption(f"Ground truth: {result.scenario.base_scenario_id}, expected rules {', '.join(result.scenario.expected_rules)}. Only alerts for this run's evidence IDs are scored. Duplicate episode mappings: {evaluation.duplicate_matches}. This is not real-world accuracy evidence.")
    if result.alerts:
        with st.container(border=True):
            st.subheader("Step 5 · Investigate the alert")
            selected = st.selectbox("Select generated alert", [alert["alert_id"] for alert in result.alerts], format_func=lambda id_: f"{services.alerts.get(id_)['detection_name']} · {short_id(id_)}", key="simulation_lab_alert")
            render_alert_workspace(services, selected, "simulation_lab_investigation")
    else:
        with st.container(border=True):
            st.subheader("Step 5 · Investigate")
            st.info("No scenario-specific alert workspace is available. The advancement of this workflow was not forced.")
    with st.container(border=True):
        st.subheader("Step 6 · Document findings and export a report")
        incidents = services.incidents.list()
        if not incidents:
            st.text("Create an incident from Step 5, then its actual persisted record will be available for status updates, notes, and nine-part reporting.")
        else:
            choices = [item["incident_id"] for item in incidents]
            preferred = st.session_state.get("active_incident_id")
            selected_incident = st.selectbox("Incident", choices, index=choices.index(preferred) if preferred in choices else 0, key="lab_incident")
            targets = st.columns(2)
            targets[0].button("Open incident investigation", key="lab_open_incident", on_click=open_incident, args=(selected_incident,), use_container_width=True)
            targets[1].button("Open security report", key="lab_open_report", on_click=open_report, args=(selected_incident,), use_container_width=True)
    st.info("No scenario in this lab indicates a confirmed attack. Review alternate explanations and validate response recommendations through authorised processes. Status changes and notes are documentation; SentinelLite does not isolate machines, block IP addresses, or reset credentials.")


def render(services) -> None:
    page_header("Security Simulation Lab", "Select a synthetic authentication scenario and trace it from raw record generation through detection, investigation, and reporting.", eyebrow="Practice lab / Controlled telemetry")
    lab = SimulationLab(services)
    definitions = {scenario.key: scenario for scenario in lab.scenarios()}
    selected_key = st.selectbox("Choose a simulation scenario", list(definitions), format_func=lambda key: definitions[key].label, key="lab_scenario_selection")
    scenario = definitions[selected_key]
    with st.container(border=True):
        st.subheader(scenario.label)
        st.text(f"Pattern: {scenario.pattern}")
        st.text(f"Why this can be suspicious: {scenario.suspicious_reason}")
        st.text(f"Investigate next: {scenario.investigation}")
        st.text(f"Alternative explanations: {scenario.alternate_explanations}")
        st.caption("No events are generated or modified by changing this selection. The Run scenario action uses current persistent rule settings and enabled states.")
    if st.button("Run simulation scenario", key="lab_run_action", type="primary", use_container_width=True):
        with st.status("Executing selected scenario through ingestion and detection…", expanded=True) as status:
            lab_result = lab.run(selected_key)
            status.update(label="Scenario completed. Each result below is from real processing on persisted records.", state="complete")
        st.session_state["lab_result"] = lab_result
        st.session_state["lab_executed_key"] = selected_key
    result = st.session_state.get("lab_result") if st.session_state.get("lab_executed_key") == selected_key else None
    if result:
        render_result(services, result)
    else:
        with st.expander("What this lab demonstrates", expanded=True):
            st.markdown("1. Labelled source events\n2. Actual parsing, UTC normalisation, and deduplication\n3. Reproducible YAML-configured detections\n4. Persisted alerts linked by evidence IDs\n5. Investigation notes, status changes, and incidents\n6. Nine-part Markdown and HTML reports\n\n**LAB BOUNDARY:** Scenarios are educational, deterministic illustrative data. They are not attack emulation on a live endpoint, and one expected signal is not proof of compromise or production accuracy.")
