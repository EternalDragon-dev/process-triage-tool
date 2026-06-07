import argparse
import json

from persistence_triage.loader import load_persistence_csv
from persistence_triage.triage import run_persistence_triage
from process_triage.audit import AuditLogger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight suspicious persistence triage (JSON-first)."
    )
    parser.add_argument(
        "--input",
        default="persistence_artifacts.csv",
        help="Path to persistence artifact CSV.",
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
    artifacts = load_persistence_csv(args.input, audit_logger=audit_logger)
    report = run_persistence_triage(
        artifacts=artifacts,
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
