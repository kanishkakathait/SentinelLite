# Data sources, provenance, and validation

SentinelLite separates **synthetic simulation data** from **public/log files supplied by a user**. Application records and example vulnerabilities must not be confused with automatically discovered findings.

## Synthetic baseline dataset

The included deterministic baseline contains **1,000 normal and 100 planted/suspicious authentication events** across 13 scenarios with separate ground truth. Every record has `simulated=true`. Source IP addresses use the documentation-only ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.

Regenerate with:

```bash
source .venv/bin/activate
python -m simulation.generate_logs
```

For a fixed reference end, use `python -m simulation.generate_logs --seed 42 --end "2026-11-25T03:00:00Z"`. The generator retains canonical hash IDs and corresponding `ground_truth.csv`. Detection evaluation is based on declared **scenario-rule pairs**, not inferred breaches or real user outcomes. Additional repeated-episode matches are separately reported rather than inflating true positives.

The separate Security Simulation Lab reuses the same scenario builders for six named demonstrations. Lab records are identified as `event_source = synthetic_lab`, `simulated = true`, and the `[SIMULATED][SIMULATION LAB: ...]` text. Runs use the real `ingest_bytes` → full-store `DetectionEngine.run()` path, not a separate alert factory. Replays report exact duplicates instead of inventing results or force-completing a scenario when configuration prevents an alert.

Lab evaluation scopes both expected evidence IDs and the active alerts linked to those IDs; other alerts in the shared store do not become free-floating false positives.

## LogHub OpenSSH public lab dataset

### Origin and licence

- **Provider:** LogPAI / LogHub
- **Dataset:** `OpenSSH_2k.log`
- **Original provenance:** An OpenSSH server in a laboratory, with logs collected over more than 28 days.
- **Upstream data file:** <https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log>
- **Upstream git blob SHA for this content entry:** `587f66b1ebf40fd59f385addc69a8b0671f34b9c`
- **LogHub licence:** <https://github.com/logpai/loghub/blob/master/LICENSE>
- **Terms checked:** Datasets freely available for research or academic work, subject to attribution and referring to LogHub.

Required citation is retained in `data/public/loghub_openssh/manifest.json` and `../THIRD_PARTY_NOTICES.md`:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics. IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.

The complete small public sample is about 220 KiB, not a downloaded repository or a selectively relabelled attack corpus. Three primary upstream resources are included byte-for-byte:

| File | Purpose |
|---|---|
| `data/public/loghub_openssh/OpenSSH_2k.log` | Full 2,000-line upstream log |
| `data/public/loghub_openssh/README.md` | Upstream collection/provenance description |
| `data/public/loghub_openssh/LICENSE_LOGHUB.txt` | Upstream licence and research-attribution requirement |

Local SHA-256 of the complete retained log:

```text
1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f
```

`manifest.json` additionally records the raw links, SHA values, a public/non-simulated label, retrieval timestamp, raw-record preservation flag, and the timestamp-reference caveats. Existing files fail loading if their computed checksum differs. Update requests never overwrite an unidentified pre-existing dataset directory. No credentials or local private logs are needed for this sample.

The **complete 2,000-line file** was bounded by both the 3 MiB download helper (compared with only 225,216 bytes of actual content) and existing ingestion limits. No truncation or prefix selection was required. **No record content, order, or labels were modified to engineer detection.** Original raw log text is retained; `raw_message` preserves each record independently of normalisation.

### Timestamp limitation

The log uses traditional syslog times such as `Dec 10 07:07:45`. These records do **not** encode a year or UTC offset.

For reproducible testing, this adapter uses **year 2015** and **UTC** as explicit normalisation conventions. They are **not verified collection-year or server-timezone facts**. Raw timestamp text remains available in every event’s `raw_message`. Off-hours evaluation interprets an explicit rule timezone after this normalisation; uncertainty in the source offset must be disclosed during analysis.

The parser supports both ordinary traditional and offset-bearing ISO log dates. Missing account, IP address, and other fields remain null. Valid general SSH/syslog messages that do not match the strict Failed/Accepted authentication form are preserved as **system** events, not forced into `authentication` or labelled as malicious.

## Verified public import result

Using the complete retained file and default configuration, the checked actual result is:

| Measure | Value |
|---|---:|
| Source records | 2,000 |
| Accepted records into initial storage | 2,000 |
| Rejected records | 0 |
| Unique normalised events from that full import | 2,000 |
| Authentication-form records | 519 |
| General system/SSH/syslog records | 1,481 |
| Simulated records in database for this source | 0 |
| Active alerts linked to this import’s evidence IDs | 222 |

The accepted, duplicate and rejected counters come from the ingestion result and SQL data—not from a manually specified percentage.

### Alert-rule breakdown for this public input

| Rule | Evidence-linked active alerts |
|---|---:|
| `SL-AUTH-001` — repeated failed authentication from one source | 77 |
| `SL-AUTH-003` — outside configured expected hours | 110 |
| `SL-AUTH-004` — privileged account authentication review | 18 |
| `SL-AUTH-005` — distinct accounts from one source | 17 |

`SL-AUTH-002` did not produce alerts for this import, and no success label was invented merely to make that rule appear productive.

Other store-wide counters (created, refreshed, superseded) can include independently imported records and must not be substituted for the selected source’s linked figure. Re-importing the same log yields:

- **0 accepted new event rows**;
- **2,000 duplicate records**;
- **0 rejected records**;
- unchanged total events and active result IDs for the same event store.

The checks assert persistence across an application restart and preserve existing incidents/notes when unrelated results are produced.

## Validation without invented correctness metrics

Trusted scenario/incident ground truth is **not supplied with the public log**. Therefore **precision, recall, and a false-positive rate are not calculated for the public import**. The observed alerts are findings for review, not proven attacks, alleged breaches, source-owning actor identifications, or proof of compromise.

The public-data UI and Markdown report show provenance, raw/normalised/duplicate/rejected counts, rules linked by evidence IDs, and limitations. Users must inspect the evidence and consider user mistakes, service messages, shared infrastructure, timezone uncertainty, unusual authorised activity, and data coverage before reaching a conclusion.

## Optional refresh and offline checks

The data used by tests is bundled under `data/public/`. Running the application or its pytest suite does not require contacting LogHub again.

The user-directed UI button uses that retained copy. To explicitly re-validate the retained provenance in a separate database:

```bash
source .venv/bin/activate
SENTINELLITE_DB_PATH=data/generated/public-validation.db \
python -c "from core.services import AppServices; from reporting.public_evaluation import load_and_evaluate_public_log; s=AppServices(); r=load_and_evaluate_public_log(s); print(r.report_markdown())"
```

The download helper is restricted to the declared LogHub raw resource URLs, 25-second request timeout and 3 MiB per-file cap. `ensure_loghub_dataset()` is only called on a user action, not as a hidden background fetch.

## Choosing and discarding datasets

Datasets are selected only after format, provenance, file size, licence and practical relevance are checked. Test credentials, private records, and production secrets are not downloaded or implied. Researchers should not infer IP ownership, current network events, attack confirmation, or an organisation-specific risk judgement from a public lab corpus alone.
