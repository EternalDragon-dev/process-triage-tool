import argparse
import json

from process_triage.audit import AuditLogger
from process_triage.loader import load_processes_csv
from process_triage.triage import run_triage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight suspicious process triage (JSON-first)."
    )
    parser.add_argument(
        "--input",
        default="processes.csv",
        help="Path to CSV input with process artifacts.",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        help="Optional path to write forensic audit events as JSONL.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--no-audit-events",
        action="store_true",
        help="Exclude audit_events from stdout JSON (still written to --audit-log).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    audit_logger = AuditLogger(enabled=True)
    processes = load_processes_csv(args.input, audit_logger=audit_logger)
    report = run_triage(
        processes=processes,
        source=args.input,
        audit_logger=audit_logger,
        include_audit_events=not args.no_audit_events,
    )

    if args.audit_log:
        audit_logger.write_jsonl(args.audit_log)

    if args.pretty:
        print(json.dumps(report, indent=2))
    else:
        print(json.dumps(report))


if __name__ == "__main__":
    main()
