# Sentinel Loop
Evidence-driven DFIR triage with deterministic wrappers, confidence revision, and forensic auditability.

## Documentation Roadmap
For student-friendly deep dives into architecture, software engineering, and cybersecurity theory using this project as a case study, see:
- `docs/README.md`
- `docs/01_system_overview.md`
- `docs/02_software_engineering_lessons.md`
- `docs/03_cybersecurity_dfir_lessons.md`
- `docs/04_self_correction_design.md`
- `docs/05_project_progress_timeline.md`
- `docs/06_glossary.md`

## What it does
- Reads a process artifact CSV (`pid`, `parent`/`ppid`, `name`, `path`, `command_line`, optional `user`).
- Applies deterministic suspicious-process rules.
- Returns structured JSON suitable for MCP/LLM pipelines.
- Captures forensic audit events and can write them as JSONL.

## Find Evil / Protocol SIFT Alignment
Sentinel Loop is designed as a custom MCP triage-and-correction layer that can sit in a Protocol SIFT workflow.
- **Custom MCP tools instead of generic shell execution:** `mcp_server.py` exposes typed tools for process/network/persistence triage and full cross-domain correction.
- **Evidence-integrity posture:** deterministic rule execution, explicit correction reasoning, audit lifecycle events, and report integrity hashes.
- **Self-correction behavior:** the correction engine raises or lowers confidence based on corroborating or missing evidence across domains.

## Reproducible Setup and Validation
Install and run with pinned dependency range:
```bash
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -p "test_*.py"
python3 correction_main.py \
  --processes-csv tests/data/processes.csv \
  --network-csv tests/data/network_connections.csv \
  --persistence-csv tests/data/persistence_artifacts.csv \
  --no-audit-events \
  --pretty
```

## Structured Error Contract
If an input file is missing or malformed, CLI and MCP wrappers return a structured error payload:
- `report_type`: `sentinel_loop.error.v1`
- `error.code`: stable machine-readable code
- `error.domain`: failing domain (`process`, `network`, `persistence`, `correction`, or `mcp`)
- `error.message`: human-readable issue summary
- `error.details`: row/column/path context where available

## Run
```bash
python3 main.py --input processes.csv --pretty --audit-log audit_log.jsonl
```

## Network Triage Wrapper
Use the network wrapper to triage suspicious connections linked to processes:
```bash
python3 network_main.py --input network_connections.csv --pretty --audit-log network_audit_log.jsonl
```

## Persistence Triage Wrapper
Use the persistence wrapper to triage cron/systemd startup artifacts:
```bash
python3 persistence_main.py --input persistence_artifacts.csv --pretty --audit-log persistence_audit_log.jsonl
```

## Correction Engine — Hypothesis-Verification-Correction Loop (Day 3)
Runs all three triage passes and cross-references findings across domains.
Each finding is assigned a revised confidence score based on corroborating or
contradicting evidence from the other domains:
- `ESCALATED` — active process + network activity + persistence installed
- `CONFIRMED_UPWARD` — at least one corroborating finding in another domain
- `DOWNGRADED` — network activity with no matching suspicious process (possible hollowing)
- `UNCONFIRMED` — no cross-domain corroboration found; confidence reduced

```bash
python3 correction_main.py \
  --processes-csv processes.csv \
  --network-csv network_connections.csv \
  --persistence-csv persistence_artifacts.csv \
  --pretty \
  --audit-log correction_audit_log.jsonl
```

## Day 5 — Accuracy & Correction Report (Public DFIR Stress Test)
### Goal
Demonstrate that Sentinel Loop does not stop at one-shot detections, but cross-references evidence across domains and revises confidence scores automatically with a forensic audit trail.

### Methodology
1. Select a public DFIR event dataset with process + network + persistence-relevant signals.
2. Transform source events into Sentinel Loop wrapper schemas:
   - process: `pid, ppid, name, path, command_line, user`
   - network: `pid, process_name, protocol, state, local_address, local_port, remote_address, remote_port, user, executable_path`
   - persistence: `artifact_type, name, path, command, user, schedule, enabled`
3. Run full correction loop (`triage_all` logic via `correction_main.py`).
4. Measure correction behavior:
   - confidence increases vs decreases
   - correction type distribution (`CONFIRMED_UPWARD`, `UNCONFIRMED`, `ESCALATED`, `DOWNGRADED`)
   - audit chain completeness (`audit_tool_invocation_started == audit_tool_invocation_completed`)
5. Record integrity hash of final report for chain-of-evidence verification.

### Dataset Provenance
- Public source: `dfirvault/ForensIQ` sample event CSV
- URL: `https://raw.githubusercontent.com/dfirvault/ForensIQ/main/test.csv`
- Local artifacts:
  - source: `stress_test_public/forensiq_test.csv`
  - transform script: `stress_test_public/transform_public_dataset.py`
  - transformed inputs:
    - `stress_test_public/public_processes.csv`
    - `stress_test_public/public_network_connections.csv`
    - `stress_test_public/public_persistence_artifacts.csv`
  - run outputs:
    - `stress_test_public/public_correction_report.json`
    - `stress_test_public/public_correction_audit_log.jsonl`
  - metrics script: `stress_test_public/analyze_stress_results.py`

### Stress Test Commands
```bash
python3 stress_test_public/transform_public_dataset.py
python3 correction_main.py \
  --processes-csv stress_test_public/public_processes.csv \
  --network-csv stress_test_public/public_network_connections.csv \
  --persistence-csv stress_test_public/public_persistence_artifacts.csv \
  --no-audit-events \
  --audit-log stress_test_public/public_correction_audit_log.jsonl \
  > stress_test_public/public_correction_report.json
python3 stress_test_public/analyze_stress_results.py
```

### Results (Public Dataset Stress Run)
- `report_type`: `sentinel_loop.correction_engine.v1`
- `integrity_sha256`: `f1aef97d16f6138fd2f8483a4f75f5e51f505c8a468db59b9060e26efe262309`
- Final `confidence_factor`: `0.800`
- Triage summary:
  - process findings: `4` (high `0`, medium `4`, low `0`)
  - network findings: `4` (high `2`, medium `2`, low `0`)
  - persistence findings: `0`
- Correction summary:
  - total corrected findings: `8`
  - `CONFIRMED_UPWARD`: `6`
  - `UNCONFIRMED`: `2`
  - `ESCALATED`: `0`
  - `DOWNGRADED`: `0`
- Confidence movement:
  - increased: `6`
  - decreased: `2`
  - unchanged: `0`
  - average shift: `+0.060`
  - max increase: `+0.10`
  - max decrease: `-0.05`
- Audit consistency:
  - total audit events: `170`
  - `audit_tool_invocation_started`: `4`
  - `audit_tool_invocation_completed`: `4`
  - invocation balance check: `PASS`

### Results Table Text (Devpost Copy-Ready)
Use the following block directly in your submission:

```text
Sentinel Loop — Public DFIR Stress Test (Day 5)
Dataset: dfirvault/ForensIQ (GitHub public sample)
Report type: sentinel_loop.correction_engine.v1
Integrity SHA-256: f1aef97d16f6138fd2f8483a4f75f5e51f505c8a468db59b9060e26efe262309
Final confidence_factor: 0.800

Triage findings:
- Process: 4 (H:0 M:4 L:0)
- Network: 4 (H:2 M:2 L:0)
- Persistence: 0

Correction outcomes:
- Total corrected findings: 8
- CONFIRMED_UPWARD: 6
- UNCONFIRMED: 2
- ESCALATED: 0
- DOWNGRADED: 0

Confidence shift:
- Increased: 6
- Decreased: 2
- Unchanged: 0
- Avg shift: +0.060
- Max increase: +0.10
- Max decrease: -0.05

Audit integrity:
- Total audit events: 170
- audit_tool_invocation_started: 4
- audit_tool_invocation_completed: 4
- Invocation balance: PASS
```

### Limitations (Transparent Evaluation Notes)
- This run uses a **public sample-sized dataset**; larger enterprise datasets are expected to exercise more rule coverage.
- Source data did not include native PID/PPID/process lineage for all event types, so schema mapping used deterministic synthetic PID alignment for cross-domain correlation.
- Persistence findings were zero under current rule criteria for this sample after normalization; this is a dataset/rule-fit outcome, not a pipeline failure.
- Ground-truth labels in this stress test are event-description-based rather than full host-forensic truth, so this should be treated as a reproducible engineering validation run (not a benchmark against a gold-standard malware corpus).

## Why This Demonstrates Self-Correction
- **It revises conclusions after verification, not before.** Initial rule findings are treated as hypotheses and then re-scored only after cross-domain evidence checks (process ↔ network ↔ persistence).
- **It can both increase and decrease confidence.** In the stress run, some findings were upgraded (`CONFIRMED_UPWARD`) while others were reduced (`UNCONFIRMED`), proving it is not a one-direction “always escalate” detector.
- **Each revision is explicit and auditable.** Every correction event stores original confidence, revised confidence, correction type, and reasoning, creating a machine-verifiable chain of evidence.
- **The correction process is deterministic and reproducible.** The same inputs generate the same correction outcomes and integrity hash behavior, which supports forensic repeatability.
- **It separates detection from validation.** Wrapper rules detect suspicious patterns; the correction engine validates or downgrades those patterns using corroboration logic, mirroring analyst workflow.
- **It is demo-visible.** In a live run, judges can see the system “change its mind” through correction event types and confidence deltas rather than static one-shot output.

## Day 7 Demo Voiceover Script (45 Seconds)
Use this narration during the live terminal demo:

“Sentinel Loop is not a one-shot malware detector — it’s an evidence-driven DFIR triage agent that can correct itself.

First, it generates initial hypotheses from process, network, and persistence artifacts using deterministic rules.
Then, instead of trusting those first findings, it cross-references evidence across domains — for example, matching suspicious process activity to live network behavior and persistence signals.

When evidence supports a finding, Sentinel Loop raises confidence.
When evidence is missing or contradictory, it lowers confidence and marks the finding as unconfirmed.
So it can move in both directions — not just escalate everything.

Every correction is logged with the original confidence, revised confidence, correction type, and reasoning, plus an integrity hash for forensic traceability.

What you’re seeing here is the key differentiator: Sentinel Loop doesn’t just detect — it validates, revises, and shows exactly why it changed its mind.”

## MCP Server Integration (Day 2 Bootstrap)
Expose all three wrappers plus the correction loop as MCP tools:
- `triage_processes`
- `triage_network`
- `triage_persistence`
- `triage_all` — full Hypothesis-Verification-Correction loop (Day 3)

Install dependency:
```bash
python3 -m pip install -r requirements.txt
```

Start MCP server over stdio:
```bash
python3 mcp_server.py
```

The server will use local CSV files by default (`processes.csv`, `network_connections.csv`, `persistence_artifacts.csv`) and each tool accepts:
- `input_path`
- `include_audit_events`
- `audit_log_path`

## Final Submission Artifact Checklist
Use this checklist before Devpost submission freeze:
- Public repository URL with complete setup and run instructions.
- Public demo video URL showing autonomous triage plus correction behavior.
- Evidence bundle references (stress-test report, audit log, integrity hash, reproducible commands).
- Architecture narrative mapping Sentinel Loop to Find Evil goals: autonomous DFIR triage, self-correction, and evidence integrity.
- Confirmed CI + tests green (`.github/workflows/ci.yml`, `tests/`).

## JSON Output
The CLI prints one JSON report with:
- `summary`: finding counts by severity
- `confidence_factor`: deterministic confidence score for this triage run
- `findings`: rule-level findings with artifact evidence
- `integrity`: SHA-256 hash of the report payload
- `audit_events` (optional): step-by-step audit trail