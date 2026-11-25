# Third-party notices

## SentinelLite project

The original SentinelLite application source is provided under the repository's MIT Licence. The MIT Licence does not replace licences or citation requirements that apply to third-party data.

## LogPAI / LogHub

A public lab-derived sample of **OpenSSH_2k.log** is bundled at `data/public/loghub_openssh/` with unmodified `README.md` and `LICENSE_LOGHUB.txt` obtained from the upstream project.

### Provenance

LogHub describes OpenSSH as a log collected from an OpenSSH server in its lab over more than 28 days. SentinelLite uses only the small `OpenSSH_2k.log` file rather than cloning the entire upstream repository.

- Dataset repository: <https://github.com/logpai/loghub>
- File provenance: <https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log>
- Upstream OpenSSH blob entry: `587f66b1ebf40fd59f385addc69a8b0671f34b9c`
- Bundle/raw log SHA-256 in this application: `1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f`
- Upstream licence: <https://github.com/logpai/loghub/blob/master/LICENSE>

### Licence statement and attribution condition

The LogHub licence says the datasets are freely available for research or academic work, subject to the condition that any usage or distribution refers to LogHub. The included `LICENSE_LOGHUB.txt` is the source document for that statement. Do not represent the file as owned by SentinelLite, as an internal/enterprise production corpus, or as relabelled SentinelLite ground truth.

### Required dataset citation

LogHub specifically requests citation of the following paper for its datasets:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics. IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023.

Related dataset-hosting metadata is available through LogHub/Zenodo at <https://zenodo.org/records/1492218>. This project’s attribution does not imply endorsement by LogPAI, LogHub, paper authors, Splunk, Microsoft, CrowdStrike, or any other company.

### Preservation and timestamp caveat

Records are imported without changing their order or contents to manufacture successful alerts. No labels are inserted. Traditional `Dec 10 07:07:45`-style timestamps omit year and timezone. SentinelLite uses 2015 and UTC explicitly as normalisation choices for reproducible ordering, not authoritative collection-time facts. Raw timestamps are retained verbatim in the standard `raw_message` representation, and source bytes/checksums remain available.

No trusted scenario ground truth or confirmed-account-compromise labels are asserted for the public log. It must not be re-described as the production telemetry, customers, or incident experience of SentinelLite or this application's user.

## Runtime libraries and development tools

The application uses Python, Streamlit, Pandas, Plotly, PyYAML, SQLite, and pytest. See `requirements.txt` for runtime dependencies. Optional screenshot/browser checks use Playwright and Ruff (`requirements-dev.txt`) and are not runtime requirements.

The normal Python dependency installation retrieves dependencies from their package repositories during setup. No paid service, proprietary security feed, commercial static sensor dependency, Docker daemon, cloud platform, or embedded enterprise SIEM service is used by the application.

The custom brand SVG is an original project asset. Interface inspiration remains conceptual; this is not a copy of Microsoft Sentinel, CrowdStrike Falcon, Splunk Enterprise Security, or any other vendor's product, logo, design assets, source code, or trademarked dashboard.

Microsoft Sentinel, CrowdStrike Falcon, and Splunk are identified in requirements as design references only and are trademarks of their respective owners. SentinelLite is an independent application; the LogHub sample is provided solely as a documented public research dataset.
