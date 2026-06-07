import argparse
import json

from process_triage.audit import AuditLogger
from network_triage.loader import load_connections_csv
from network_triage.triage import run_network_triage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight suspicious network triage (JSON-first)."
    )
    parser.add_argument(
        "--input",
        default="network_connections.csv",
        help="Path to network artifact CSV.",
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
    connections = load_connections_csv(args.input, audit_logger=audit_logger)
    report = run_network_triage(
        connections=connections,
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
