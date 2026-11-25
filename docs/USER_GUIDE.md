# SentinelLite operator guide

## Quick start and persistence

Start with `source .venv/bin/activate` followed by `streamlit run app.py`. Open `http://localhost:8501`. Stop with Ctrl+C. `data/sentinellite.db` is the default persistent database and `SENTINELLITE_DB_PATH` can override it for a separate environment.

Turn on **Demo Mode** in the sidebar for immediate labelled synthetic data. Repeating the load is idempotent: identical events become duplicates rather than new records; analyst notes, incidents, and remediation records remain. Turning the switch off does **not** delete data.

Use `SENTINELLITE_DB_PATH=data/generated/practice.db streamlit run app.py` for a disposable practice workspace without touching the default database.

## Supported log inputs

Uploads must be UTF-8 text, no larger than 10 MiB and no more than 100,000 records. Accepted extensions are `.csv`, `.json`, `.jsonl`, `.log`, and `.txt`.

### CSV

Headers are case-insensitive and common field aliases are normalised. Timestamps are required. Recommended headers:

```text
timestamp,event_source,hostname,source_ip,destination_ip,username,event_category,event_action,authentication_result,raw_message
```

### JSON

A single object, an array of flat records, an object with an `events` array, and newline-delimited JSON objects are supported. Nested arrays/objects are not accepted as values for normalised scalar fields.

Example:

```json
{
  "timestamp": "2026-11-25T10:00:00+11:00",
  "event_source": "identity-provider",
  "hostname": "demo-idp",
  "source_ip": "203.0.113.10",
  "username": "demo-user",
  "event_category": "authentication",
  "event_action": "login",
  "authentication_result": "failure",
  "raw_message": "Authorised local synthetic example"
}
```

### Linux SSH authentication

`.log` and `.txt` expect `sshd` lines containing `Failed password`, `Accepted password`, `Failed publickey`, `Accepted publickey`, or keyboard-interactive equivalents, with a hostname and source IP. ISO-8601 timestamps retain their offset. Traditional `Nov 25 10:00:00` timestamps use the selected timezone and current local year.

Example:

```text
2026-11-25T10:00:00+11:00 demo-host sshd[1234]: Failed password for invalid user demo from 203.0.113.10 port 2022 ssh2
```

Use only your own authorised logs or generated records. The importer never executes uploaded commands and cannot verify whether a string contains sensitive personal information; create a sanitised copy before uploading potentially sensitive logs.

### Timestamps and missing values

Offset-aware timestamps are converted to UTC. Naive timestamps use the upload/form-configured timezone. Invalid/missing timestamps reject only that record. Missing usernames/IPs/hosts become null and are not replaced with fake entities.

Duplicates are identified from canonical event content, not file names. This means two personally different events that look completely identical in the source cannot be distinguished and will count as duplicates. If your source has a unique event ID, preserve it in `raw_message` to make source identity distinguishable by this educational implementation.

## Page guide

### 1. SOC Overview

KPI cards query the current database. Configure the event/alert window using last hour, 24 hours, seven days, or a local custom date range. Empty periods show clear empty states rather than fabricated charts. Select a recent alert to open its evidence workspace directly.

**Events processed today** uses ingestion timestamps during the selected local calendar day; the other event timeline uses event occurrence timestamps. **Open incidents** includes Open, Investigating, and Contained. Resolved/Closed incidents constitute the resolved count; average resolution duration uses persisted create-to-resolution timestamps when available.

### 2. Security Events

Choose a file, select the timezone for naive timestamps, and submit. The summary shows received, accepted, exact duplicates, and rejected records along with capped per-record errors. Choose automatic detection if desired. The event explorer filters exact entities/categories and raw-message text. Raw log content is displayed as plain text, not executable content.

**Generate synthetic files** writes a fresh current dataset under `data/generated` and offers a download. This is different from enabling Demo Mode, which loads the included `data/sample` dataset automatically.

### 3. Threat Detection

Run all configured enabled rules over all persisted events. The result counts created, refreshed, superseded/inactive, and total active findings. Rule threshold updates run a new recomputation after saving.

Upload custom ground truth only if it matches the ingested event IDs and expected scenarios. Ground truth columns are `event_id`, `scenario_id`, `scenario_label`, and pipe-separated `expected_rules`. Evaluation uses scenario/rule pairs, not raw event counts, and reports duplicate mappings separately.

Expected sample result for the delivered fixed dataset is TP=18, FP=0, FN=0, precision=100%, and recall=100%. This is not a real-world effectiveness guarantee.

### 4. Security Alerts

Filter by severity, rule, status, exact source/account, local date range, or active/history state. Sort columns in the table and select an alert to inspect:

- rule explanation and severity justification;
- structured event metadata and triggered entity scope;
- chronological supporting events and raw messages;
- persistent notes by category;
- recommended actions and alert status controls;
- explainable correlation suggestions and explicit incident creation.

New, Investigating, Resolved, False Positive, and Closed are supported. Status edits are audit-recorded. A **Superseded** mark means recomputation no longer produces that alert in the active set; it does not erase the historic investigation.

Direct link format: `?page=security-alerts&alert_id=<actual-alert-id>`.

### 5. Incident Investigation

Create a case with one or more explicitly selected alerts. Correlation suggestions require at least two shared entities (source IP, user, or hostname) plus temporal proximity; no automatic merge occurs.

Record initial observations, evidence, alternate explanations, false-positive considerations, risk assessment, response recommendations, and conclusions. The timeline combines supporting log events, detections, alert creation, notes, and incident status changes.

Statuses are Open, Investigating, Contained, Resolved, and Closed. Containment is an analyst assertion only; SentinelLite performs no containment. A resolution summary is required for Resolved/Closed. Reopening and subsequent re-resolution are retained in history.

Direct link format: `?page=incident-investigation&incident_id=<actual-incident-id>`.

### 6. Vulnerability & Risk Register

Create manual entries or import the structured CSV template. Capture CVE/CVSS only from a trusted supplied source, affected asset, asset criticality, exposure, available evidence, recommended remediation, owner, due date, evidence, and verification date. Fields marked optional may remain null.

Statuses are Open, In Progress, Remediated, Verified. Verification requires an actual date. **Overdue** combines a past due date with Open/In Progress status.

Custom priority is not CVSS: severity contributes 0–40, asset criticality 6–30, exposure 5–20, and evidence 2–10. P1 starts at 80, P2 at 60, P3 at 40. Experts should still validate any risk-ranking inputs against organisational criteria.

The Add DEMO action inserts repeatable labelled synthetic records only; it does not scan any system.

### 7. Security Reports

Select a persisted incident to generate Markdown and print-friendly HTML in memory from the same records. Every report contains executive summary, details, findings, timeline, risk/uncertainty, recommendations, false positives, and conclusion.

Download buttons use actual exports. HTML and Markdown protect record-derived text appropriately. For PDF, open/save the HTML and use browser **Print → Save as PDF**; no bundled PDF renderer is claimed.

### 8. Detection Rules

Read algorithm and false-positive guidance before changing configuration. Enable/disable a rule or change supported thresholds, business hours, timezone, day-of-week setting, privileged users, or filters. Save causes recomputation and preserves analyst state.

Sample dry runs use the included labelled sample scenario and do **not** persist new alerts. The YAML is custom and Sigma-inspired only, not full Sigma compatibility.

### 9. Settings & Documentation

Store a default analyst name and selected timezone. The default display/naive-upload timezone is separate from per-rule off-hours timezone configuration.

The documentation viewer contains this guide, architecture, and detection guide. Audit records and storage counts show live local state.

## Phase 2 enhancements

### Dashboard and alert navigation
KPI cards link to corresponding investigation areas. Event/category windows filter only their stated live SQL aggregates. Use the horizontal detection/status charts to compare rules by severity, source or type. The activity feed follows stored events/alerts/notes/status history and offers an inspector; it is not guaranteed to be continuously live.

On **Security Alerts**, combine exact source/account/status/rule/date filters with free-text search. Choose severity/time ordering and page size before selecting a numbered result or full investigation workspace. Short display IDs are only for readability; the complete ID remains visible underneath. Scope-related leads are suggestions, not proof of shared attack ownership.

### Security Simulation Lab
**Monitoring → Security Simulation Lab** contains six scenario types. Changing the selection alone does not generate or reclassify data. **Run simulation scenario** uses the real JSON ingestion, timestamp normalisation, complete-store reconciliation and persisted alert mapping. Use the six resulting panels to trace evidence, counters, linked alert IDs, scoped evaluation, notes/incidents and reports. Replays identify duplicates; disabling a rule does not force a fake result.

Review alternative explanations before classifying suspicious behaviour. Quick investigation/status actions and incident creation save real state but never execute endpoint rotation, containment, password resets, or network blocking.

### Visual incidents and nine-part reports
In **Incident Investigation**, associated detections and affected entities link back to persisted records. The visual timeline uses red failure, green success, orange detection, blue alert-created, and purple analyst markers. **Inspect evidence** retrieves the event/alert/note/status record corresponding to that node, including exact UTC timestamps/reference IDs. The full accessible table retains the same ordered history.

In **Analyst notes**, edit an existing note by identifier, observing that creation time is preserved and edits appear in the audit trail. Follow the supported Open → Investigating → Contained → Resolved → Closed workflow. Reopening clears the stale active resolution summary, not its history.

**Security Reports** generates nine sections using a single shared aggregate for both formats: executive summary, overview, detection details, timeline, supporting event evidence, analyst findings, recommended actions, incident status and limitations/uncertainty. Markdown and branded HTML retain fresh provenance and notes/status data; dedicated PDF is not claimed, though HTML supports browser Print→PDF locally.

### Public dataset validation
Under **Security Events → Public dataset validation**, import the complete bundled LogHub OpenSSH sample to exercise real auth/syslog parsing and count detected rules. The panel exposes source bytes, accepted/rejected/duplicate counts, provenance, source-linked alert evidence and a Markdown validation report. Missing legacy year/offset fields use explicit reference conventions described on-screen rather than allegations of original collection time.

The public adapter never invents precision, recall or compromise verdicts. It keeps generic valid messages as system records and missing user/IP fields null. Replaying identical content marks duplicates without deleting or synthesising external telemetry.

### Risk-mode configuration and reduced motion
**Vulnerability & Risk Register** computes its five cards from the manual register. Filter by severity, remediation status, priority, owner, and free-text keyword; view corresponding severity and remediation distribution data. Existing owners, supplied evidence and due dates persist across edits. **Verified** requires a verification date and is discrete from Remediated, P1/P2 severity ranking and CVSS.

Use the sidebar **Reduced motion** switch or Settings option to disable Plotly transitions persistently. OS reduced-motion preferences are also respected by CSS. Keyboard focus outlines and touch-sized controls complement the responsive layout. Charts retain ordinary text labels and full tables do not rely on colour alone.

## Sharing and GitHub workflow

`.gitignore` excludes the virtual environment, browser downloads, actual local databases, generated current datasets, and common secret/config files. Review `git status --short` before committing. Never include user logs, credentials, API keys, personal documents, `.env`, or `.streamlit/secrets.toml`.

Only documentation screenshots use a dedicated isolated temporary SQLite database under `data/generated`, which is automatically cleaned up after capture. Runtime screenshots can be regenerated with approved development tooling as documented in the README. A browser binary is not required for everyday use.

## Troubleshooting

- **Command not found:** activate `.venv`, or invoke `.venv/bin/streamlit` directly from the project root.
- **Port in use:** run `streamlit run app.py --server.port 8502` and open that port.
- **Database locked:** stop duplicate runs against the same database and retry. Use separate database paths for independent practice.
- **No findings:** verify `event_category=authentication`, `authentication_result=success/failure`, timestamps in the intended timezone, non-null entity fields, enabled rules, and threshold/window values. Check whether a later recomputation made a previous match inactive.
- **Unexpected off-hours alerts:** check the event's original timezone offset and the configured rule timezone rather than assuming server time.
- **Missing chart:** select a wider time range. Empty states are intentional rather than fake data.
- **Fresh evaluation after upload:** rerun detection so late and out-of-order events are reconsidered.
- **Browser capture unavailable:** Playwright is optional dev tooling, not a runtime requirement. Install `requirements-dev.txt` and Chromium as described in the README only if screenshots need regeneration.
