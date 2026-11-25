# SentinelLite acceptance checklist

This checklist is derived from the project brief. An item is complete only after its implementation and verification are recorded.

## Runtime and architecture

- [x] Installs in a local virtual environment on ARM64 macOS without Docker or external accounts.
- [x] Starts with `streamlit run app.py`; all application data persists in SQLite after restart.
- [x] Uses actual database records for metrics and alerts; no hardcoded findings or dashboard totals.
- [x] Clearly identifies simulated records and educational/non-production boundaries.

## All nine navigation targets

- [x] SOC Overview: eight real-data KPI groups; event-volume, severity, authentication, and source-IP views; selectable recent-alert evidence.
- [x] Security Events: CSV, JSON/NDJSON, and Linux SSH-auth upload; validation, malformed-record results, persistent filtering and raw-event inspection.
- [x] Threat Detection: runnable detection, rule results, scenario evidence, ground-truth evaluation, and caveats.
- [x] Security Alerts: filters, sortable records, persistent statuses, notes, evidence timelines, and incident creation.
- [x] Incident Investigation: multi-alert creation, explainable suggestions, status history, affected entities, notes, chronological timeline, and resolution summary.
- [x] Vulnerability & Risk Register: manual/CSV records, explainable custom priority, evidence, remediation workflow, overdue and progress views.
- [x] Security Reports: record-derived Markdown and HTML downloads with every required report section and safe escaping.
- [x] Detection Rules: documentation, enable/disable, persistent threshold changes, and dry-run sample tests.
- [x] Settings & Documentation: demo controls, persistent analyst settings, architecture, limitations, and operating guidance.

## End-to-end security operations workflow

- [x] Generate at least 1,000 normal and 100 suspicious synthetic records with reserved documentation IPs and ground truth.
- [x] Ingest generated events, store accepted rows, identify exact duplicates, and report rejected records.
- [x] Detect brute force, failure-then-success, off-hours authentication, privileged activity, multiple-account attempts, and correlated indicators.
- [x] Produce persistent alerts with event evidence, targeted accounts, timestamps, explanations, severity rationale, and recommendations.
- [x] Investigate an alert, create an incident, add notes, update statuses, and export its report.
- [x] Restart without losing events, alerts, notes, incidents, settings, or remediation records.

## Reprocessing semantics

Event IDs are SHA-256 hashes of canonical normalised event content. Re-importing identical content is idempotent; identical timestamp/content records that cannot be distinguished in a source log are treated as duplicates and documented as such. Alert IDs are hashes of rule ID, stable episode anchor, and entity scope. Recurring episodes have distinct anchors. Each detection run sorts the complete event set in UTC and recomputes non-overlapping episodes. Existing matching alerts retain analyst status, notes, and incident links while evidence is refreshed. Alerts absent from the new result become inactive rather than being deleted, preserving investigation history; they are excluded from current KPIs. An earlier-arriving event can therefore create a new active episode and supersede the previous one.

Out-of-order input affects correlation only after the next detection run. Incident and alert timelines always re-sort evidence; no result depends on ingestion order. Off-hours calculations use an explicit configured IANA timezone, while database timestamps use fixed-width UTC ISO-8601 with six microsecond digits for range-correct lexical comparisons. Existing datetime columns are canonicalised at startup without deleting saved work. The application timezone setting persists and is used by upload and metric services after restart.

## Untrusted content and report safety

Imported or analyst-entered values are displayed with plain-text, dataframe, and code primitives rather than enabled raw HTML or untrusted Markdown. HTML reports escape every imported or analyst-supplied field. Markdown reports collapse untrusted line breaks and escape HTML plus Markdown links/images, table delimiters, and markup punctuation. Uploaded logs are never executed. Database values use parameters, upload sizes and record counts are bounded, parser failures have controlled errors, and sample error lists are capped.

## Evaluation semantics

Evaluation units are expected `(scenario_id, rule_id)` pairs, not raw event labels. Ground truth declares the expected rules for each planted scenario. An alert is attributed to every scenario represented in its supporting event IDs. Exact expected-pair matches count as true positives; unsupported scenario-rule matches and alerts without planted evidence count as false positives; unmatched expected pairs count as false negatives. Multiple alerts for the same scenario-rule pair do not inflate true positives and are reported separately as duplicate match count. Precision and recall are scenario-detection metrics with no claim of production effectiveness.

## Quality and delivery

- [x] Automated tests cover parsers, empty/malformed inputs, missing fields, timestamps/timezones, out-of-order and duplicate events, recurring attacks, reimports/restarts, all detections, statuses, incidents, risk calculation, safe reports, persistence, all ten UI pages and major interaction workflows.
- [x] Full test suite and Streamlit smoke checks pass with recorded output.
- [x] README contains architecture, stack, macOS commands, walkthrough, rule guidance, evaluation, screenshots where capture tooling permits, limitations, and future work.
- [x] No implementation claim is made for unavailable PDF export, real-time collection, enterprise SIEM/EDR, automatic containment, or external integrations.
