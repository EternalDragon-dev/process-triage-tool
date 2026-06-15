from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from correction_engine.engine import run_correction_loop
from process_triage.loader import load_processes_csv
from process_triage.triage import run_triage
from validation import InputValidationError


class SentinelLoopRegressionTests(unittest.TestCase):
    def test_process_triage_detects_encoded_powershell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "processes.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["pid", "ppid", "name", "path", "command_line", "user"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "pid": "101",
                        "ppid": "1",
                        "name": "powershell.exe",
                        "path": r"C:\Users\alice\AppData\Local\Temp\powershell.exe",
                        "command_line": "powershell.exe -enc aQBlAHgA",
                        "user": "alice",
                    }
                )

            processes = load_processes_csv(str(csv_path))
            report = run_triage(processes=processes, source=str(csv_path), include_audit_events=False)
            rule_ids = {finding["rule_id"] for finding in report["findings"]}
            self.assertIn("R001_ENCODED_POWERSHELL", rule_ids)
            self.assertGreaterEqual(report["summary"]["total_findings"], 1)

    def test_correction_loop_is_deterministic_for_fixed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            processes_csv = root / "processes.csv"
            network_csv = root / "network_connections.csv"
            persistence_csv = root / "persistence_artifacts.csv"

            with processes_csv.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["pid", "ppid", "name", "path", "command_line", "user"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "pid": "100",
                        "ppid": "1",
                        "name": "powershell.exe",
                        "path": r"C:\Users\alice\AppData\Local\Temp\powershell.exe",
                        "command_line": "powershell.exe -enc aQBlAHgA",
                        "user": "alice",
                    }
                )
                writer.writerow(
                    {
                        "pid": "200",
                        "ppid": "1",
                        "name": "explorer.exe",
                        "path": r"C:\Windows\explorer.exe",
                        "command_line": "explorer.exe",
                        "user": "alice",
                    }
                )

            with network_csv.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "pid",
                        "process_name",
                        "protocol",
                        "state",
                        "local_address",
                        "local_port",
                        "remote_address",
                        "remote_port",
                        "user",
                        "executable_path",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "pid": "100",
                        "process_name": "powershell.exe",
                        "protocol": "TCP",
                        "state": "ESTABLISHED",
                        "local_address": "10.0.0.1",
                        "local_port": "50000",
                        "remote_address": "8.8.8.8",
                        "remote_port": "4444",
                        "user": "alice",
                        "executable_path": r"C:\Users\alice\AppData\Local\Temp\powershell.exe",
                    }
                )
                writer.writerow(
                    {
                        "pid": "200",
                        "process_name": "explorer.exe",
                        "protocol": "TCP",
                        "state": "ESTABLISHED",
                        "local_address": "10.0.0.1",
                        "local_port": "50001",
                        "remote_address": "9.9.9.9",
                        "remote_port": "4444",
                        "user": "alice",
                        "executable_path": r"C:\Windows\explorer.exe",
                    }
                )

            with persistence_csv.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["artifact_type", "name", "path", "command", "user", "schedule", "enabled"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "artifact_type": "cron",
                        "name": "evil-cron",
                        "path": "/tmp/evil.sh",
                        "command": "powershell.exe -enc aQBlAHgA",
                        "user": "alice",
                        "schedule": "* * * * *",
                        "enabled": "true",
                    }
                )

            report = run_correction_loop(
                processes_csv=str(processes_csv),
                network_csv=str(network_csv),
                persistence_csv=str(persistence_csv),
                include_audit_events=False,
            )

            correction_types = {entry["correction_type"] for entry in report["corrected_findings"]}
            self.assertIn("ESCALATED", correction_types)
            self.assertIn("CONFIRMED_UPWARD", correction_types)
            self.assertIn("DOWNGRADED", correction_types)

    def test_process_loader_rejects_missing_required_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "bad_processes.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["pid", "name"])
                writer.writeheader()
                writer.writerow({"pid": "1", "name": "cmd.exe"})

            with self.assertRaises(InputValidationError):
                load_processes_csv(str(csv_path))


if __name__ == "__main__":
    unittest.main()
