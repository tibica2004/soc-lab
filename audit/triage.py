#!/usr/bin/env python3
"""
triage.py — marcheaza un finding ca triat, ca sa nu mai apara.

Baseline-ul e memoria sistemului: ce ai reparat sau ce ai stabilit ca fals
pozitiv nu se mai afiseaza. Fara el, aceleasi findings apar la fiecare rulare
si dupa a doua oara nimeni nu se mai uita.

    python3 triage.py app/config.py CWE-200 --reason "fals pozitiv, nimic sensibil"
    python3 triage.py app/x.py '*' --reason "fisier de test"
    python3 triage.py --list
"""
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

BASELINE = Path(__file__).resolve().parent / "baseline.json"

def load():
    if not BASELINE.exists():
        return []
    try:
        return json.loads(BASELINE.read_text()) or []
    except json.JSONDecodeError:
        print("baseline.json corupt", file=sys.stderr); raise SystemExit(1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file_path", nargs="?")
    p.add_argument("cwe", nargs="?", help="CWE-89 sau * pentru tot fisierul")
    p.add_argument("--reason", default="", help="de ce, pentru cine citeste peste 3 luni")
    p.add_argument("--list", action="store_true")
    p.add_argument("--remove", action="store_true", help="scoate din baseline")
    a = p.parse_args()

    entries = load()

    if a.list:
        if not entries:
            print("baseline gol")
        for e in entries:
            print(f"  {e.get('cwe','*'):10} {e.get('file_path')}"
                  f"   {e.get('reason','')}")
        return 0

    if not a.file_path or not a.cwe:
        p.error("file_path si cwe sunt necesare (sau --list)")

    fp = a.file_path.lstrip("./")
    cwe = a.cwe.upper()

    if a.remove:
        before = len(entries)
        entries = [e for e in entries
                   if not (e.get("file_path") == fp and e.get("cwe","*").upper() == cwe)]
        BASELINE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
        print(f"scos {before - len(entries)} intrari")
        return 0

    if any(e.get("file_path") == fp and e.get("cwe","*").upper() == cwe for e in entries):
        print(f"deja in baseline: {fp} {cwe}")
        return 0

    entries.append({
        "file_path": fp,
        "cwe": cwe,
        "reason": a.reason,
        "added_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    BASELINE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))
    print(f"adaugat: {fp} {cwe}"
          f"{'  — ' + a.reason if a.reason else ''}")
    print(f"{len(entries)} intrari in baseline")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
