#!/usr/bin/env python3
"""
Sentinel Loop – Correction Engine CLI (Day 3)

Runs all three deterministic triage passes, then cross-references findings
across process, network, and persistence domains to produce a unified
CorrectionReport with revised confidence scores and a full audit trail.

Usage:
    python3 correction_main.py \
        --processes-csv processes.csv \
        --network-csv network_connections.csv \
        --persistence-csv persistence_artifacts.csv \
        --pretty \
        --audit-log correction_audit_log.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys

from correction_engine.engine import run_correction_loop
from process_triage.audit import AuditLogger


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel Loop – Hypothesis-Verification-Correction engine"
    )
    parser.add_argument(
        "--processes-csv",
        default="processes.csv",
        help="Path to process artifact CSV (default: processes.csv)",
    )
    parser.add_argument(
        "--network-csv",
        default="network_connections.csv",
        help="Path to network connections CSV (default: network_connections.csv)",
    )
    parser.add_argument(
        "--persistence-csv",
        default="persistence_artifacts.csv",
        help="Path to persistence artifacts CSV (default: persistence_artifacts.csv)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--no-audit-events",
        action="store_true",
        help="Exclude audit_events array from JSON output",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        default=None,
        help="Write forensic audit log as JSONL to this path",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    audit_logger = AuditLogger(enabled=True)

    report = run_correction_loop(
        processes_csv=args.processes_csv,
        network_csv=args.network_csv,
        persistence_csv=args.persistence_csv,
        include_audit_events=not args.no_audit_events,
        audit_log_path=args.audit_log,
        audit_logger=audit_logger,
    )

    indent = 2 if args.pretty else None
    sys.stdout.write(json.dumps(report, indent=indent))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
