# Phase 2 verification record

Verification date: **25 November 2026**

This describes the delivered SentinelLite Phase 2 state. Values below refer to the executed application and bundled deterministic/public fixtures, not to hypothetical untested behaviour.

## Environment used

- macOS 26.7 on ARM64 (Apple Silicon)
- Python 3.14.9
- Git 2.50.1
- Project-local `.venv`
- Project-local Playwright/Chromium development browser
- No Docker, VM, paid API, external production SIEM or live security feed

Pre-enhancement baseline: **48 passing tests and clean Ruff**. A source-only backup was created at `backups/sentinellite-pre-phase2.tar.gz` with SHA-256:

```text
b9c230fd179aebd22535ce3df508f7fc920638dc45a5cf60bc4016d2723a774d
```

The environment rejected creation of the initial `.git` directory. No Git commit, push, remote, or `git status` success is claimed; the pre-enhancement archive is the actual available checkpoint. Git-ignored directories cover backups, virtual environments, browser binaries, caches, generated data and test databases.

## Full-suite output

```bash
source .venv/bin/activate
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
```

Recorded final output:

```text
........................................................................ [ 90%]
........                                                                 [100%]
80 passed in 28.04s
All checks passed!
```

Ruff is configured with `E4`, `E7`, `E9` and `F` under `[tool.ruff.lint]` in `pyproject.toml`. There is no configured type checker to claim separately. Streamlit `AppTest` exercises navigation and buttons with real record-bearing services. Three Playwright cases exercise actual responsive browser layouts.

## Functional and regression coverage

### Original runtime and data contracts

The pre-existing ingestion and detection behaviours remain covered:

- CSV/JSON arrays, single objects and JSONL, plus Linux SSH authentication;
- invalid/empty files, malformed records/timestamps, UTF-8, limits and oversized CSV/parser fields;
- fixed-width UTC and explicit/naive timezone handling, duplicate IDs and existing timestamp canonicalisation;
- source/entity/IP validation and null fields that must not import invented identities;
- brute force, distinct-account patterns, success-after-failures, privileged context, off-hours sessions, correlated indicators;
- duplicate events/alerts, same and recurring episodes, thresholds, out-of-order and late events, inactive history and notes preservation;
- incident/alert statuses, notes, resolution validations, status reopens, and restart persistence;
- semantic Markdown/HTML escaping, precision/recall calculation, custom vulnerability priority versus CVSS, and remediation verification.

### Phase A presentation and dashboard

- Severity/time sorting and clamped pagination.
- Live database-derived activity entries spanning events, detections, notes, and status changes.
- Related-alert retrieval by shared source IP, account, or hostname without automatic attack merging.
- Navigable KPI widgets, richer chart types and reduced-motion styling. Navigation deep links for alert and incident records are preserved.

### Phase B investigation and reporting

- Exact chronological event/detection/alert/note/status ordering with failure/success/analyst markers and underlying references.
- Audited editable notes with original creation timestamps and independently recorded `investigation_note_edited` audit entries.
- The supported `Open → Investigating → Contained → Resolved → Closed` workflow, including reopen cleanup without deleting historical transitions.
- Nine-section reports over a shared aggregate: executive summary, incident overview, detection details, chronological timeline, supporting evidence, analyst findings, recommended actions, incident status, limitations and uncertainty.
- Raw HTML/Markdown payload rejection of dangerous markup, image link syntax, table delimiters, multiline content, and imported untrusted text.

### Phase C six-step simulation

All six lab patterns run the real ingestion/detection services:

1. Brute force
2. Password spraying
3. Suspicious successful login
4. Privileged activity
5. Off-hours activity
6. Correlated suspicious authentication evidence

Assertions cover actual expected linked alert counts, evidence-scoped TP/FN/FP metrics, non-duplicated replays with unchanged total events, disabled rules without forced alerts, unrelated incident preservation, and restart persistence of results/notes/statuses.

### Phase D public LogHub import

The retained public `OpenSSH_2k.log` is exactly the 225,216-byte full upstream sample with this SHA-256:

```text
1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f
```

Actual parser and database outcomes:

| Measure | Verified outcome |
|---|---:|
| Source records | 2,000 |
| Initially accepted records | 2,000 |
| Initial duplicate records | 0 |
| Malformed/unsupported records | 0 |
| Unique normalised event IDs for that import | 2,000 |
| Authentication-form records | 519 |
| Other SSH/general syslog records preserved as system events | 1,481 |
| Active alerts linked to these source event IDs | 222 |
| Records marked simulated for this source | 0 |

Evidence-linked rule counts:

- `SL-AUTH-001`: **77**
- `SL-AUTH-003`: **110**
- `SL-AUTH-004`: **18**
- `SL-AUTH-005`: **17**

The parser initially missed traditional timestamp normalisation on generic valid messages because of the branch order. That defect was corrected and the entire unmodified original file was reprocessed under a fresh test database to obtain the results above. The test also checks that source raw text remains unchanged.

Replaying the complete input returns **0 accepted new events, 2,000 duplicates, 0 rejected records**, keeps event totals unchanged and preserves IDs over restart. Checksum mismatches and oversize downloads are rejected before database writes. `simulated` remains false for the actual public corpus.

The log's licence and citation are bundled with source bytes and checksum. `manifest.json`, `OpenSSH_2k.log`, `README.md`, and `LICENSE_LOGHUB.txt` are included under `data/public/loghub_openssh/`.

**No trusted scenario ground truth is supplied. Precision, recall and false-positive rates are not asserted for the public dataset.** The report describes the produced counters and findings, not confirmed attacks or system-wide detection accuracy.

### Phase E vulnerability and accessibility checks

- P1/P2/open/overdue/remediated/verified values are calculated from the current manual register.
- Severity/status/priority/owner/keyword filters and deterministic due-date/priority/discovery/severity sort behaviour.
- Owner, remediation notes, source evidence, verification timestamps and remediation-action records persist after restart.
- A persisted Reduced motion preference is saved through an actual widget interaction and sets Plotly layout transition duration to 0.
- The default Plotly transition is 250 ms when preference is not enabled.

### Browser validation

Three genuine temporary-Chromium cases covered:

| Viewport | Assertion evidence | Artefact |
|---|---|---|
| 1440 px desktop | Complete app and dynamic counts; no unintended page-level overflow | `docs/screenshots/responsive-desktop.png` |
| 900 px tablet | Same complete, data-backed interface and layout checks | `docs/screenshots/responsive-tablet.png` |
| 390 px mobile | Same checks plus reduced-motion computed CSS (`animationName: none`) | `docs/screenshots/responsive-mobile.png` |

The browser test runtime uses an automatically cleaned temporary SQLite database. Assertions check actual completed module rendering and absence of Streamlit exceptions. These are targeted responsive tests, not exhaustive certification across devices, browsers, networks, zoom levels or a professional accessibility audit.

## Current screenshots

Actual running application captures:

- `soc-overview.png`
- `security-events.png`
- `threat-detection.png`
- `simulation-lab.png`
- `alert-investigation.png`
- `incident-management.png`
- `vulnerability-register.png`
- `security-reports.png`
- `public-data-validation.png`

Plus the three responsive viewport captures listed above. Templates/static illustrations were not substituted for running application images. The capture command uses a temporary application server and demo store and stops it in `finally`.

## Original synthetic baseline still intact

The deterministic sample comprises **1,000 normal plus 100 suspicious/planted events**, **13 ground-truth scenarios**, and **21 resultant demo detections**. The expected baseline scenario-rule evaluation remains **18 true positives, 0 false positives, 0 false negatives** under default rules. Repeated episode mappings are counted separately so they cannot inflate true-positive counts.

## Explicitly bounded/unimplemented functionality

The following are not hidden implementation claims:

- Dedicated PDF export, live enterprise agent collection, full Sigma compatibility, vulnerability scanning, threat-intelligence APIs, and endpoint control are not implemented.
- No role-based production auth, HA deployment, tamper-proof audit infrastructure, external threat containment, endpoint isolation, firewall change, credential reset, or IP blocking occurs.
- No real-world accuracy/exploitability/production efficacy claim is inferred from synthetic scenarios or unlabelled public data.
- Full-store recomputation and bounded manual files are aimed at a defensible local application, not unlimited real-time telemetry.

The exact acceptance checklist is maintained in [`acceptance.md`](acceptance.md); enhancements and Review Notes remain recorded in [`REVIEW_NOTES.md`](REVIEW_NOTES.md). Public collection, licence, timestamp convention and data limitations are documented in [`DATASETS.md`](DATASETS.md).
