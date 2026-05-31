# ThreatSucker / ngo-intel

ThreatSucker is an inspectable threat-intelligence collection and reduction scaffold for Luxembourgish NGOs. The Python package is currently named `ngo_intel`, but the CLI also exposes the `threatsucker` command.

The first implementation is fixture-based. It does not require API keys, databases, LLM calls, or network access.

## Standalone And scan-assess Use

ThreatSucker is a standalone Python project. It can be run directly with the `ngo_intel` package or `threatsucker` CLI to collect, reduce, score, explain, and inspect NGO-focused threat intelligence.

When used with scan-assess, the wrapper in `modules/threatsucker/runner.py` runs the configured ThreatSucker mode and contributes its reduced intelligence and correlation output as scan-assess telemetry. scan-assess-gui can discover the module, enable or disable it, show config files, and start/open the local ThreatSucker controls page when available.

ThreatSucker owns source configuration, scoring rules, allowlists, local NGO context, and its web controls. scan-assess and scan-assess-gui consume the resulting telemetry and use it as context for reports and validation.

In the wider telemetry suite, ThreatSucker answers: which external threat-intelligence items are relevant enough to pass to an operator or LLM, and why?

## Modes

ThreatSucker has two modes:

```text
mini  - profile-based collection, no scoring
smart - local-context scoring and triage brief generation
```

Mini mode is the MVP path. It answers:

```text
What compact threat information should an AI receive for this kind of organization?
```

Smart mode is the later path. It answers:

```text
What matters to this specific NGO, given its DNS logs, assets, services, and user context?
```

## Mini Profiles

Mini mode is driven by YAML profiles in `config/profiles/`.

The current profile is:

```text
config/profiles/luxembourg_ngo.yaml
```

It focuses on high-impact, simple, parsable context for Luxembourgish NGOs:

- phishing
- credential theft
- invoice fraud
- donation/payment impersonation
- malware delivery URLs
- major vulnerability context
- Luxembourg and neighbouring-country terms
- common NGO payment/document/cloud brands

## Why Python

Python 3.11+ keeps the project approachable for students and NGO technologists. The implementation uses small functions, explicit Pydantic models, plain CSV/JSONL files, and Typer commands that can be inspected without learning a large framework.

## Why CSV and JSONL

Raw feeds are evidence. Normalized files are analyst data. Scored files are triage data. Agent context is the final reduced intelligence.

CSV files are easy to open in spreadsheet tools. JSONL files preserve structured fields such as tags, reasons, and evidence lists. Every stage writes files to disk so a reviewer can trace why an item appeared in the final brief.

## Directory Structure

```text
config/                 scoring, source, allowlist, and org profile config
data/raw/               raw fixture/source evidence
data/normalized/        normalized indicators and vulnerabilities by date
data/scored/            scored triage outputs by date
data/agent_context/     compact current agent context
local_context/          NGO domains, brands, assets, DNS, and user context
src/ngo_intel/          Python package
tests/fixtures/         local sample feed and context evidence
```

## Pipeline Stages

Mini mode:

1. Normalize available fixture/raw source data.
2. Filter it using the selected mini profile.
3. Write a no-scoring AI context pack under `data/mini/current/`.

Smart mode:

1. `normalize`: reads raw/fixture files and writes normalized indicator and vulnerability CSV/JSONL.
2. `score`: compares normalized intelligence with local NGO context and writes relevance scores with reason strings.
3. `brief`: reduces scored data to compact files under `data/agent_context/current`.
4. `run`: executes all three stages.

## How To Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m ngo_intel init
python -m ngo_intel modes
python -m ngo_intel mini profiles
python -m ngo_intel mini run
python -m ngo_intel overview
python -m ngo_intel overview --json
python -m ngo_intel highlight-dnscap
python -m ngo_intel filter-enumeros path/to/enumeros-output.json
python -m ngo_intel smart run
python -m ngo_intel show top
python -m ngo_intel explain --value login-example-ngo-support.lu
pytest
```

After reinstalling the editable package, the same mode commands are available through:

```bash
threatsucker mini run
threatsucker smart run
```

Optional local web interface:

```bash
threatsucker web
```

Then open:

```text
http://127.0.0.1:8765
```

## How To Inspect Results

Look at:

- `data/mini/current/ai_context.md`
- `data/mini/current/ai_context.json`
- `data/mini/current/ngo_relevance_brief.md`
- `data/mini/current/ngo_relevance_brief.json`
- `data/mini/current/deep_evidence.json`
- `data/mini/current/threat_items.jsonl`
- `data/mini/current/threat_items.csv`
- `data/mini/current/domains.csv`
- `data/mini/current/urls.csv`
- `data/mini/current/vulnerabilities.csv`
- `data/mini/current/evidence_index.json`
- `data/mini/current/dnscap_highlights.md`
- `data/mini/current/enumeros_findings.md`
- `data/normalized/YYYY/MM/DD/indicators.csv`
- `data/normalized/YYYY/MM/DD/vulnerabilities.csv`
- `data/scored/YYYY/MM/DD/relevant_indicators.csv`
- `data/scored/YYYY/MM/DD/dns_matches.csv`
- `data/scored/YYYY/MM/DD/risk_items.jsonl`
- `data/agent_context/current/intel_brief.md`
- `data/agent_context/current/evidence_index.json`

The `explain` command is the demo-friendly path for one item:

```bash
python -m ngo_intel explain --value login-example-ngo-support.lu
```

It prints the indicator, score, priority, every reason string, local matches, recommended actions, and raw evidence path.

## Human And Machine Outputs

ThreatSucker writes parallel outputs:

```text
Markdown = human-readable summaries
JSON     = chatbot/pipeline-readable summaries
JSONL    = item streams
CSV      = spreadsheet/debug inspection
```

The most important mini-mode files are:

- `ngo_relevance_brief.md`: compact report for humans.
- `ngo_relevance_brief.json`: compact report for software/AI.
- `deep_evidence.json`: fuller drill-down evidence store.

The report references `deep_evidence.json` by stable IDs such as:

```text
threat:5a41b142e9bd3793
dns:18d91ba65e4a96e5
inventory:7c1d42dcb1231007
```

This keeps the report small while preserving depth for an AI that needs to inspect evidence.

## Scoring Logic

Scoring lives in `src/ngo_intel/scoring.py`; rule weights live in `config/scoring_rules.yaml`.

The scorer starts at zero, adds the source weight, applies local relevance boosts such as DNS matches, brand mentions, Luxembourg context, and phishing/credential-theft relevance, then applies penalties such as allowlisted domains or no local match. Every score adjustment appends a readable reason string, for example:

```text
+40 matched_dns_query: login-example-ngo-support.lu seen in DNS logs
-100 allowlisted_domain: microsoft.com
```

Priority bands are:

- `critical`: 90+
- `high`: 70+
- `medium`: 45+
- `low`: 20+
- `archive`: below 20

## Fixture-Based Sources

Current source adapters are intentionally simple:

- MISP-style event JSON normalization
- URLhaus-style JSONL URL records
- PhishTank lookup JSON
- CIRCL Vulnerability-Lookup-style CVE JSONL fixture

## DNScap And Enumeros Context

DNScap highlighting compares DNS queries against domains from the current mini threat pack:

```bash
python -m ngo_intel highlight-dnscap
python -m ngo_intel highlight-dnscap --dns path/to/dns.csv
```

It writes:

- `data/mini/current/dnscap_highlights.md`
- `data/mini/current/dnscap_highlights.csv`
- `data/mini/current/dnscap_highlights.jsonl`

Enumeros filtering accepts stored JSON collected from any supported platform:

```bash
python -m ngo_intel filter-enumeros path/to/windows-enumeros.json
python -m ngo_intel filter-enumeros local_context/imported/enumeros/
```

For a live local run, pass an Enumeros binary for the current host platform:

```bash
python -m ngo_intel run-enumeros /path/to/enumeros
```

Stored JSON is preferred for cross-platform collection because Windows, macOS, and Linux hosts can produce their own Enumeros output and send it back for later filtering.

## External Software Integration

External software can call the CLI or import `ngo_intel.pipeline`.

```python
from ngo_intel.pipeline import build_mini_pack, collect_live_and_build_pack

result = build_mini_pack("/srv/threatsucker")
print(result["relevance_brief_json"])
print(result["deep_evidence_json"])
```

See [docs/EXTERNAL_PIPELINE.md](docs/EXTERNAL_PIPELINE.md).

For a visual terminal overview:

```bash
threatsucker overview
```

For AI/software callers:

```bash
threatsucker overview --json
```

## Documentation Map

- [Architecture](docs/ARCHITECTURE.md)
- [Profiles](docs/PROFILES.md)
- [Local collectors: DNScap, Enumeros, SafeSniff](docs/LOCAL_COLLECTORS.md)
- [External pipeline/API use](docs/EXTERNAL_PIPELINE.md)
- [Flask web interface](docs/WEB_UI.md)
- [Quiz extension plan](docs/QUIZ_EXTENSION.md)
- [Packaging and deployment](docs/PACKAGING.md)

## Future Integrations

The adapter files are TODO-ready for:

- CIRCL MISP OSINT feed manifest and event JSON files
- CIRCL Vulnerability-Lookup API
- PhishTank URL checking API with optional `app_key`
- URLhaus by abuse.ch community API
- Other URL reputation feeds where evidence can be preserved locally

## Limitations

- This is triage support, not attribution.
- Source confidence varies.
- Do not automatically block based only on one low-confidence source.
- Agent context is deliberately reduced and should not contain raw feed dumps.
- Raw evidence is preserved for auditability.
