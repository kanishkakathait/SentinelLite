# Detection rules

Defaults are versioned in `detection/rules/*.yaml` and inserted into `detection_rules` on startup. Changes made in the GUI persist in SQLite and take precedence on subsequent runs; changing a YAML file does not silently overwrite analyst configuration.

All findings are suspicious activity requiring analyst review. None proves credential compromise, malicious source ownership, or a need for automatic containment.

## SL-AUTH-001 — Repeated failed authentication from one source

- **Default severity:** Medium
- **Trigger at defaults:** five failures for one account from one source IP within 300 seconds
- **Evidence:** triggering failed events, source, account, first/last timestamps, attempt count, and target list
- **Method:** group by `(source_ip, username)`, sort chronologically, then emit non-overlapping threshold episodes
- **Known limitations:** missing source/account events are excluded. Exact duplicates cannot be distinguished if the logs contain no unique event ID. Delayed logs can change an episode after another detection run.
- **False positives:** password-manager mistakes, expired cached credentials, authorised vulnerability testing, service restarts, and user error.
- **Initial review:** compare VPN/host context, recent known failures, lockout notices, and authorised testing. Validate with the account owner before response changes.

## SL-AUTH-002 — Successful authentication after repeated failures

- **Default severity:** High
- **Trigger at defaults:** a success preceded by at least five failures within 300 seconds, with the same source IP and account
- **Evidence:** the prior failures plus successful event, with its event ID recorded explicitly
- **Method:** chronological correlation for each `(source_ip, username)` since the preceding success
- **Known limitations:** shared sources, incomplete telemetry, successful token/SSO flows, and missing application context. It does not identify which person authenticated.
- **False positives:** forgotten passwords followed by a correct login, administrator-assisted recovery, or test credentials.
- **Initial review:** confirm with the user/system owner; inspect source and subsequent successful actions before considering password reset or stronger MFA.

## SL-AUTH-003 — Authentication outside expected hours

- **Default severity:** Low
- **Default context:** 08:00–18:00 in `Australia/Melbourne`, with optional account/host filters and day-of-week behaviour
- **Trigger:** any authentication event outside configured hours, grouped into source/account/host sessions separated by more than one hour
- **Method:** convert stored UTC timestamps to the configured IANA timezone before comparing local time
- **Known limitations:** Daylight-saving and business schedules vary. One-hour sessions reduce repeated alert noise but are not real application session identifiers.
- **False positives:** shift work, travel, after-hours maintenance, scheduled jobs, clock errors, and incorrect timezone configuration.
- **Initial review:** validate approved after-hours work and time sources; consider timing only with other evidence.

## SL-AUTH-004 — Privileged account authentication review

- **Default severity:** Informational
- **Default accounts:** `root`, `administrator`, `admin`
- **Trigger:** authentication involving a configured privileged account, grouped by account/source/host session
- **Method:** case-insensitive account-name configuration and temporal grouping
- **Known limitations:** naming conventions differ; not every privileged identity is listed and matching strings do not establish privileges at the target host.
- **False positives:** normal administration is expected to be common. This rule is intentionally not a generic privileged-login compromise alert.
- **Initial review:** reconcile with an authorised change or maintenance record, consider role/source/host, and review subsequent privileged actions.

## SL-AUTH-005 — Multiple distinct accounts from one source

- **Default severity:** High
- **Trigger at defaults:** failures against five distinct usernames from one source within 300 seconds
- **Evidence:** targeted account list, distinct-account count, failure timeline, and source
- **Method:** independent rolling episode logic counts distinct usernames rather than failure volume for one account
- **Known limitations:** usernames might be invalid; shared gateways can aggregate users; organisation-specific normalisation may be needed. It is described as password-spraying-like or enumeration behaviour rather than a diagnosis.
- **False positives:** shared proxies, batch provisioning, authorised security assessment, and service discovery.
- **Initial review:** examine target diversity, source ownership, approved testing documents, and related identity-provider logs.

## SL-AUTH-006 — Correlated suspicious authentication indicators

- **Default severity:** High
- **Trigger at defaults:** the prior-failure indicator plus at least one additional indicator among unusual timing and privileged account
- **Indicators shown in evidence:** repeated failures, off-hours success, privileged account
- **Method:** follows the failure/success grouping independently and explains every contributing indicator in the alert rationale
- **Known limitations:** indicators are not independent statistical probabilities, and this is not machine learning or risk-scored identity analytics.
- **False positives:** urgent administrative recovery after hours, repeated legitimate failures before an authorised maintenance login, or incorrect hours configuration.
- **Initial review:** inspect all signals and supporting events, contact authorised owners, and apply organisational incident-response procedures only after verification.

## Duplicate, reorder, and disablement behaviour

Rule changes initiate a full recomputation when saved in the interface. Disabling a rule makes its old active findings inactive while retaining analyst history. Re-enabling can reactivate matching deterministic findings. Findings with notes or incident links are not deleted when malformed, late, or disabled inputs change the active episode set.

Use **Detection Rules → Test against a sample scenario** for isolated dry runs. These synthetic tests do not create alerts or incidents.

## Relationship to Sigma

The YAML structure is **Sigma-inspired**, not a full implementation of Sigma. Keys such as `rule_id`, `name`, `description`, `severity`, `config`, documentation, and recommendations support this application's typed detector dispatch. Sigma selection modifiers, aggregation syntax, field mappings, pipelines, log-source products, backends, and complete schema validation are not implemented.

An illustrative translation—not an import file understood by this application—might look like:

```yaml
title: Repeated failed authentication from one source
status: experimental
logsource:
  category: authentication
detection:
  selection:
    authentication_result: failure
  condition: selection
```

Production correlation would still need source/account count aggregation and a five-minute timeframe in a correctly validated Sigma or SIEM backend. SentinelLite performs this episode logic directly in `detection/scenarios.py`; claiming full Sigma compatibility without implementing the specification would be misleading.

## Extending a detector

1. Add focused, realistic synthetic fixtures and expected-rule ground truth first.
2. Give the rule a unique ID and document scope, thresholds, assumptions, and false positives.
3. Write a pure detector under `detection/scenarios.py` with deterministic UTC sorting and non-overlapping episode semantics.
4. Register the detector in `DETECTORS` and add its YAML default.
5. Add tests for missing fields, missing timestamps, malformed configuration, out-of-order input, repeated reprocessing, recurring episodes, disabled rules, and benign events.
6. Keep analyst state out of pure detection logic; use `DetectionEngine.run()` to synchronize records transactionally.
7. Document evaluation unit, precision/recall denominator, and any expected scenario-rule labels.

Performance claims should be based on measured representative logs rather than the small fixture suite alone. Typical fields remain optional because real telemetry often lacks usernames, hosts, or addresses.
