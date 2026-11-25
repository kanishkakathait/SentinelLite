from __future__ import annotations

import pandas as pd
import streamlit as st

from core.config import GENERATED_DATA_DIR
from ingestion.public_datasets import DATASET_DIRECTORY, DATASET_DOWNLOADS
from pages.common import page_header, render_events
from simulation.generate_logs import generate_dataset


def manual_ingestion(services) -> None:
    st.info("Uploaded content is parsed as plain text and is never executed. Maximum upload: 10 MiB and 100,000 records. Accepted dates are stored in fixed-width UTC.")
    with st.container(border=True):
        st.subheader("Log ingestion")
        with st.form("log_ingestion"):
            upload = st.file_uploader("Security log file", type=["csv", "json", "jsonl", "log", "txt"], help="JSON arrays, an events object, single objects, NDJSON, and Linux SSH authentication logs are supported.")
            timezone_options = ["Australia/Melbourne", "UTC", "Australia/Sydney", "Australia/Brisbane"]
            timezone = st.selectbox("Timezone for timestamps without an offset", timezone_options, index=timezone_options.index(services.settings.get("timezone", "Australia/Melbourne")))
            run_detection = st.checkbox("Run detection automatically after ingestion", value=True)
            if st.form_submit_button("Validate and ingest", type="primary", use_container_width=True):
                if upload is None:
                    st.error("Choose a log file first.")
                else:
                    try:
                        result = services.ingestion.ingest_bytes(upload.name, upload.getvalue(), default_timezone=timezone)
                        st.session_state["last_ingestion"] = upload.name
                        st.session_state["last_ingestion_result"] = result
                        st.session_state["last_detection"] = services.detection.run() if run_detection else None
                    except ValueError as error:
                        st.error(str(error))
    result = st.session_state.get("last_ingestion_result")
    if result:
        st.subheader("Ingestion result")
        st.text(st.session_state["last_ingestion"])
        columns = st.columns(4)
        columns[0].metric("Records seen", result.received)
        columns[1].metric("Accepted", result.accepted)
        columns[2].metric("Exact duplicates", result.duplicates)
        columns[3].metric("Rejected", result.rejected)
        st.text(result.issue_summary)
        if result.errors:
            st.warning("Some records were not accepted. Only the first 100 errors are retained per batch.")
            st.dataframe(pd.DataFrame([issue.__dict__ for issue in result.errors]), use_container_width=True, hide_index=True)
        else:
            st.success("No malformed records were reported.")
        detection = st.session_state.get("last_detection")
        if detection:
            st.info(f"Detection: {detection.created} new · {detection.refreshed} refreshed · {detection.superseded} superseded · {detection.active} active")
    with st.expander("Generate reproducible synthetic logs"):
        st.caption("Creates 1,000 normal and 100 suspicious SIMULATED records plus ground truth in data/generated. No network activity occurs.")
        if st.button("Generate synthetic files"):
            metadata = generate_dataset(GENERATED_DATA_DIR)
            st.success(f"Generated {metadata['total_events']:,} records in {GENERATED_DATA_DIR}.")
        generated_file = GENERATED_DATA_DIR / "synthetic_events.json"
        if generated_file.exists():
            st.download_button("Download generated JSON", generated_file.read_bytes(), "synthetic_events.json", "application/json")


def public_validation(services) -> None:
    st.subheader("Public dataset validation · LogHub OpenSSH")
    st.text("Import a complete 2,000-line OpenSSH lab sample released for research/academic work with attribution. This is public lab evidence—not trusted ground-truth labels for a detection-accuracy score.")
    with st.container(border=True):
        st.text("Provenance and safeguards")
        st.text("Source: LogPAI/LogHub OpenSSH_2k.log · 225,216 bytes")
        st.text("Records are parsed as untrusted UTF-8 text. No commands are executed. The source bytes are not edited, relabelled, replayed out of order, or expanded to engineer findings.")
        st.caption("Legacy entries have no year/offset. For reproducibility, year 2015 and UTC are explicit normalisation assumptions only—not verified collection facts. Exact original timestamp text remains in raw_message.")
        st.text("Dataset type: public LogHub collection · simulated = false. IP addresses and accounts are fields from the released laboratory log.")
    if st.button("Import and validate public security log", key="load_public_evaluation", type="primary", use_container_width=True):
        with st.status("Validating public records through normalisation and detection…", expanded=True) as status:
            completed = context_when_complete(services)
            if completed:
                status.update(label="Public dataset imported and evidence-linked evaluation completed", state="complete")
            else:
                status.update(label="Public dataset import did not complete", state="error")
    result = st.session_state.get("public_evaluation")
    if not result:
        with st.expander("File preview and licence before import", expanded=False):
            manual_public_preview(services)
        return
    metadata, evaluation = result
    st.success("Import and detection completed using the stored public source bytes. The counts below are from this import, not from a separate demo result.")
    counters = st.columns(5)
    counters[0].metric("Source records", evaluation.raw_record_lines)
    counters[1].metric("Accepted (new)", evaluation.ingestion.accepted)
    counters[2].metric("Normalised IDs", len(evaluation.normalised_event_ids))
    counters[3].metric("Duplicated source records", evaluation.ingestion.duplicates)
    counters[4].metric("Rejected", evaluation.ingestion.rejected)
    duplicate_explanation = st.columns(2)
    duplicate_explanation[0].metric("Parsed authentication records", evaluation.authentication_event_count)
    duplicate_explanation[1].metric("Alerts linked to source", len(evaluation.linked_alerts))
    if evaluation.ingestion.duplicates:
        st.info("Identical timestamp/content source records collapse under the document's event deduplication model. Replaying an identical file should not create new event records or misleading alert totals.")
    if evaluation.ingestion.errors:
        with st.expander("Malformed or unsupported-record samples"):
            st.dataframe(pd.DataFrame([issue.__dict__ for issue in evaluation.ingestion.errors]), use_container_width=True, hide_index=True)
    if evaluation.ingestion.rejected:
        st.warning(f"{evaluation.ingestion.rejected} records were rejected and capped in the result sample. They are not silently converted to suspicious events.")
    st.subheader("Triggered detections scoped to this file")
    if evaluation.rules:
        st.dataframe(pd.DataFrame([{"rule_id": rule_id, "detection_name": name, "associated_alerts": count} for rule_id, name, count in evaluation.rules]), use_container_width=True, hide_index=True)
        selected = st.selectbox("Inspect public-data alert evidence", [alert["alert_id"] for alert in evaluation.linked_alerts], key="public_alert_inspection")
        with st.expander("Raw evidence and persistent alert explanation", expanded=False):
            alert = services.alerts.get(selected)
            st.text(alert["explanation"])
            st.text(alert["severity_justification"])
            render_events(services.alerts.evidence(selected), f"public_import_{selected}")
    else:
        st.info("No active alerts link to the supplied evidence. This is treated as a detection result, not as permission to invent findings.")
    st.caption(f"Full-store detection counters: {evaluation.detection.created} created, {evaluation.detection.refreshed} refreshed, {evaluation.detection.superseded} superseded. Other previously stored records can be included in those global counters.")
    st.warning("Precision, recall, and false-positive rates: not calculated. This public log does not supply trusted incident/scenario truth labels. Findings still require human validation against raw evidence and false-positive alternatives.")
    st.download_button("Download Markdown evaluation and provenance", evaluation.report_markdown().encode("utf-8"), "loghub-openssh-evaluation.md", "text/markdown", key="public_evaluation_report_file")
    manual_public_preview(services, metadata)


def context_when_complete(services) -> bool:
    from ingestion.public_datasets import load_loghub_events
    from reporting.public_evaluation import evaluate_public_bytes
    try:
        metadata, content = load_loghub_events()
        st.session_state["public_evaluation"] = (metadata, evaluate_public_bytes(services, metadata, content))
        return True
    except (ValueError, UnicodeDecodeError) as error:
        st.error(f"Public dataset validation could not complete: {error}")
        return False


def manual_public_preview(services, metadata=None) -> None:
    with st.expander("Provenance, licence, and raw source details", expanded=False):
        if metadata is None:
            metadata = services_manifest_preview()
            if metadata is None:
                return
        st.text(metadata["provenance"])
        st.text(metadata["license"])
        st.text(metadata["citation"])
        st.text(metadata["timestamp_note"])
        st.text(f"Source records modified to manufacture detections: {metadata['raw_records_modified']}")
        st.text(f"Captured local SHA-256: {metadata['downloaded_sha256']}")
        st.json({"upstream_git_blob_shas": metadata["upstream_git_blob_shas"], "source_urls": metadata["source_urls"]})
        st.text(f"Local public-source directory: {DATASET_DIRECTORY}")
        st.caption("The full README.md and LICENSE_LOGHUB.txt are bundled byte-for-byte alongside the log. External URLs are shown as provenance references, not fetched continuously by application views.")
        for filename, url in DATASET_DOWNLOADS.items():
            st.text(f"{filename}: {url}")


def services_manifest_preview():
    try:
        from ingestion.public_datasets import ensure_loghub_dataset
        return ensure_loghub_dataset()
    except ValueError:
        st.warning("Public data is not yet present locally and could not be validated. Review network access and the source licence before downloading.")
        return None


def event_explorer(services) -> None:
    st.subheader("Normalised event explorer")
    left, middle, right = st.columns(3)
    source_ip = left.text_input("Source IP (exact)", placeholder="203.0.113.10")
    username = middle.text_input("Username (exact)", placeholder="alice")
    category = right.selectbox("Event category", ["All", "authentication", "system", "uncategorised"])
    search = st.text_input("Search raw log message", placeholder="Search text without executing it")
    records = services.events.search(source_ip=source_ip.strip() or None, username=username.strip() or None, category=None if category == "All" else category, text=search or None)
    if not records:
        st.info("No events match these filters. Upload a file or enable Demo Mode.")
    else:
        st.caption(f"Showing up to 5,000 matches · {len(records):,} displayed · raw values remain plain text · exact source/query filters are SQL-parameterised")
        st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True, on_select="rerun", selection_mode="single-row", key="event_explorer_rows")
    with st.expander("Recent ingestion batches"):
        batches = services.ingestion_batches()
        if batches:
            st.dataframe(pd.DataFrame(batches), use_container_width=True, hide_index=True)
        else:
            st.info("No ingestion batches have been recorded.")


def render(services) -> None:
    page_header("Security events", "Process untrusted local logs or validate a complete public OpenSSH sample using bounded, provenance-labelled ingestion.", eyebrow="Monitoring / Data ingestion & validation")
    upload, public, explorer = st.tabs(["Ingest local logs", "Public dataset validation", "Event explorer & batches"])
    with upload:
        manual_ingestion(services)
    with public:
        public_validation(services)
    with explorer:
        event_explorer(services)
