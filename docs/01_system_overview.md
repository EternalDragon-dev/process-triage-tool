# 01 — System Overview
## Project mission
Sentinel Loop is a lightweight DFIR triage system that detects suspicious activity and then validates those findings across multiple evidence domains before finalizing confidence.

## Core idea
Most simple systems do this:
- detect once
- report once

Sentinel Loop does this instead:
1. Detect
2. Verify
3. Revise
4. Log everything

This is the **Hypothesis → Verification → Correction** pattern.

## Architectural components
### 1) Process triage (`process_triage/`)
- Input: process CSV
- Output: process findings + severity + report hash + optional audit events
- Example rules:
  - encoded PowerShell
  - suspicious execution path
  - fake `svchost.exe` location

### 2) Network triage (`network_triage/`)
- Input: network connections CSV
- Output: network findings + confidence factors + report hash
- Example rules:
  - high-risk external ports
  - LOLBin outbound activity
  - exposed RDP listener

### 3) Persistence triage (`persistence_triage/`)
- Input: persistence artifacts CSV
- Output: persistence findings + confidence factors + report hash
- Example rules:
  - suspicious temp path persistence
  - downloader-execute chains in cron
  - hidden userspace agents

### 4) Correction engine (`correction_engine/`)
- Input: outputs from all three domains
- Output: revised confidence values, correction reasons, correction events
- Correction types:
  - `CONFIRMED_UPWARD`
  - `UNCONFIRMED`
  - `ESCALATED`
  - `DOWNGRADED`

### 5) Audit layer (`process_triage/audit.py`)
- Captures tool invocation lifecycle and forensic events
- Provides JSONL log output for machine-verifiable evidence trails

### 6) MCP server (`mcp_server.py`)
- Exposes tools for assistant/agent orchestration:
  - `triage_processes`
  - `triage_network`
  - `triage_persistence`
  - `triage_all`

## Why this design matters
- **Reliability:** deterministic rule behavior
- **Traceability:** audit events + integrity hash
- **Interpretability:** explicit reason for each confidence change
- **Extensibility:** modular wrappers allow adding new data sources
