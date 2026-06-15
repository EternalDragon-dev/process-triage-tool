import csv
import re
from pathlib import Path
from urllib.parse import urlparse
BASE = Path(__file__).resolve().parent
SRC = BASE / "forensiq_test.csv"

rows = list(csv.DictReader(SRC.open(newline="", encoding="utf-8")))

pid_map = {}
pid = 2000
for r in rows:
    p = (r.get("process") or "").strip().lower()
    if p and p not in pid_map:
        pid_map[p] = pid
        pid += 137

proc_out, net_out, pers_out = [], [], []

for i, r in enumerate(rows, start=1):
    name = (r.get("process") or "").strip()
    if not name:
        continue
    key = name.lower()
    user = (r.get("username") or "UNKNOWN").strip() or "UNKNOWN"
    cmd = (r.get("command_line") or "").strip()
    file_path = (r.get("file_path") or "").strip()
    reg_path = (r.get("registry_path") or "").strip()
    ev = (r.get("event_type") or "").strip().lower()
    src_ip = (r.get("source_ip") or "").strip()
    dst_ip = (r.get("destination_ip") or "").strip()

    proc_out.append(
        {
            "pid": pid_map[key],
            "ppid": 4,
            "name": name,
            "path": file_path or name,
            "command_line": cmd or name,
            "user": user,
        }
    )

    if ev in {"networkconnect", "networksend"} or (src_ip and dst_ip and src_ip != dst_ip):
        m = re.search(r"https?://([^\s/]+)", cmd)
        remote_port = None
        if m:
            remote_port = urlparse("http://" + m.group(1)).port or (443 if "https://" in cmd else 80)
        if remote_port is None:
            remote_port = 443 if ev == "networkconnect" else 80
        net_out.append(
            {
                "pid": pid_map[key],
                "process_name": name,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "local_address": src_ip or "0.0.0.0",
                "local_port": 50000 + i,
                "remote_address": dst_ip or "0.0.0.0",
                "remote_port": remote_port,
                "user": user,
                "executable_path": file_path or name,
            }
        )

    if ev in {"registryset", "serviceinstall", "servicestart"}:
        pers_out.append(
            {
                "artifact_type": "systemd" if "service" in ev else "launchd",
                "name": name,
                "path": reg_path or file_path or "UNKNOWN",
                "command": cmd or name,
                "user": user,
                "schedule": "",
                "enabled": "true",
            }
        )

if not pers_out:
    pers_out.append(
        {
            "artifact_type": "unknown",
            "name": "none",
            "path": "UNKNOWN",
            "command": "none",
            "user": "UNKNOWN",
            "schedule": "",
            "enabled": "false",
        }
    )

def write_csv(path, rows_data):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_data[0].keys()))
        w.writeheader()
        w.writerows(rows_data)

write_csv(BASE / "public_processes.csv", proc_out)
write_csv(BASE / "public_network_connections.csv", net_out)
write_csv(BASE / "public_persistence_artifacts.csv", pers_out)

print(len(proc_out), len(net_out), len(pers_out))
