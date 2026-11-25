# Review findings and retained regressions

A read-only final review checked the primary workflows and edge cases. The following findings were addressed before the frozen 48-test/Ruff verification run.

| Finding | Resolution | Regression evidence |
|---|---|---|
| Untrusted Markdown links, images, line breaks, and table pipes could become active report markup | Imported/analyst-entered values use plain-text UI primitives. `report_generator.markdown_text` escapes HTML and Markdown structure and collapses untrusted line breaks | `tests/test_workflows.py` includes script markup, newline, remote-image, and pipe payloads |
| Variable-width UTC strings made SQL range comparisons order fractional timestamps incorrectly | `core/time_utils.to_storage` always stores six microsecond digits. Database initialisation normalises older stored datetime columns across all record tables | `tests/test_regressions.py::test_fixed_width_timestamps_preserve_range_boundaries_and_migrate` |
| Password-spray incidents omitted all targeted users when the primary alert entity was intentionally unset | Incident entity derivation now uses alert evidence, not only the primary alert field. Alert username filters also search evidence IDs | `test_password_spray_incident_and_filter_retain_all_targeted_users` |
| Saved timezone settings were not applied to ingestion/metrics after restart | The application services load saved settings unless a timezone is explicitly overridden; upload selection uses the same setting | `test_saved_timezone_is_applied_after_restart` |
| Unknown rule timezones raised an uncaught exception from the settings form | Detection configuration converts `ZoneInfoNotFoundError` into the form-handled `ValueError` | `test_invalid_rule_timezone_is_a_validation_error` |
| A non-object JSON record or malformed NDJSON line yielded incorrect counters and could discard later valid events | Array/line values reach per-record normalisation errors; malformed NDJSON lines are counted and processing continues | `test_malformed_json_records_are_counted_and_do_not_abort_valid_records` |
| Reopened incidents preserved stale final resolution summaries and report conclusions | Reopening clears the active resolution fields; executive/conclusion text is conditional on Resolved/Closed status while status history remains intact | `test_reopening_clears_stale_resolution_summary_and_report_conclusion` |
| A whitespace-padded vulnerability CSV identifier could bypass duplicate detection and cause an uncaught database constraint error | Identifiers are canonicalised before duplicate checks and SQL constraint failures are reported as duplicate records rather than unhandled UI errors | Duplicate CSV test in `tests/test_workflows.py` uses a padded existing ID |

The final defensive-input pass also handles parser-level oversized CSV fields as batch errors and displays uploaded filenames/analyst-note metadata as plain text. Screenshot capture now uses an isolated automatically cleaned-up temporary database, avoiding pollution of saved work and event growth after format normalisation.

## Phase 2 evidence reviewed

After the baseline corrections were completed, the enhancement was implemented as an incremental layer without resetting existing functionality or producing a separate hardcoded alert route.

- The premium visual system retains persistent data and interactive business logic: original brand SVG, navigation groups, safe severity/status styling, live KPI navigation, real activity/entity inspection, pagination and severity-aware sorting.
- Timeline markers map to the same security events, detections, alerts, notes and history IDs used by incident reports, while an accessible full table and text-only evidence remain available. Note editing retains original timestamps and records edit audits in `audit_log`.
- Six small simulation scenarios execute the real ingestion and full-store detection path. Replays report actual duplicate counts and preserve unrelated incidents and notes; they do not conjure successful runs when thresholds or enabled configurations do not match.
- Public validation includes the complete proper LogHub `OpenSSH_2k.log` rather than a selectively modified attack corpus. Its licence, citation, source SHA, complete 2,000-record input, general SSH message handling, missing timestamp facts, false-positive boundaries and replay outcomes are explicit throughout the UI and documentation.
- All five risk-register summary values are computed from supplied vulnerability records. Custom priority is not represented as CVSS or as a vendor-scanner result.
- Accessibility checks actively exercise persisted reduced-motion preference, Plotly transition duration 0, CSS reduced-motion behaviour and actual desktop/tablet/mobile browser layouts. Screenshots reflect those running views rather than authored mock-ups.

The final executed result is **80 tests passed in 28.04 seconds plus a clean Ruff run**. It includes all ten navigation targets, six lab scenarios, public plaintext log validation and three actual Chromium viewport checks.

The checkpoint for this enhancement is the pre-enhancement source-only archive at `backups/sentinellite-pre-phase2.tar.gz`, checksum `b9c230fd179aebd22535ce3df508f7fc920638dc45a5cf60bc4016d2723a774d`. This environment did not authorise creating new `.git` metadata during autonomous operation, so no Git commit or remote push is being claimed; other runtime files are Git-ignored to permit a clean future initialise/commit by the user.

See [`VERIFICATION.md`](VERIFICATION.md) for the recorded full-suite/static-check outputs and [`acceptance.md`](acceptance.md) for the requirement checklist.
