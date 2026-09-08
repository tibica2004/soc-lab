#!/usr/bin/env python3
"""
hunt.py — ramura Antares a auditului. Emite SARIF, ca sa intre in fuse.py.

Ruleaza `code_scanner.scan()` pentru fiecare ipoteza CWE din hypotheses.txt si
converteste rezultatele in SARIF 2.1.0, compatibil cu ce emite Semgrep.

DIFERENTA DE GRANULARITATE, importanta pentru interpretare:
Semgrep raporteaza fisier + linie + regula. Antares raporteaza doar FISIER --
modelul nu produce numere de linie. In SARIF asta apare ca `startLine: 1`,
care e o conventie, nu o localizare. `fuse.py` grupeaza pe fisier tocmai ca sa
compare marul cu marul; nu interpreta linia 1 ca pe un rezultat.

CE NU FACE: nu cere modelului un verdict. `scan()` primeste repo si CWE si
intoarce fisiere candidate. Daca ceva e vulnerabil sau nu se decide in aval,
prin coroborare cu alte surse. Motivul e masurat: TNR 0.0 pe repouri
patch-uite -- modelul raporteaza vulnerabilitati in toate.

Utilizare:
    python3 hunt.py --repo ~/soc-lab/sample_repo --out runs/test
    python3 hunt.py --repo ... --cwe CWE-78            # o singura ipoteza
    python3 hunt.py --repo ... --hypotheses lista.txt
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# code_scanner sta in harness/, nu aici
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "harness"))

from code_scanner import DEFAULT_CACHE, scan  # noqa: E402


def read_hypotheses(path: Path) -> list[str]:
    """O ipoteza CWE per linie; comentariile si spatiile se ignora."""
    out: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.upper().startswith("CWE-"):
            out.append(line.upper())
    return out


MAX_FILES = 3  # peste atat, localizarea e dispersata (O-005) -- zgomot


def sarif_document(results: list, repo: Path, absolute_paths: bool) -> dict:
    """
    Construieste SARIF 2.1.0 din rezultatele scanarilor.

    Caile: Semgrep emite absolute pe masina de rulare, iar fuse.py le
    normalizeaza cu relpath fata de --repo. Emitem in acelasi format ca sa
    fie sigur ca gruparea pe fisier se face pe aceeasi cheie.
    """
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for res in results:
        if len(res.files) > MAX_FILES:
            continue  # dispersat: nu e localizare, e enumerare
        cwe = res.cwe_id
        rule_id = f"antares.{cwe.lower()}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"Antares localization for {cwe}",
                "shortDescription": {
                    "text": f"Fisier candidat pentru {cwe}, localizat de Antares"
                },
                "fullDescription": {
                    "text": (
                        f"Modelul a returnat acest fisier ca posibil continand "
                        f"{cwe}. Localizare la nivel de fisier, fara linie. "
                        f"Nu e un verdict -- cere coroborare."
                    )
                },
                "properties": {
                    "tags": ["antares", "external/cwe/" + cwe.lower()],
                    "cwe": [cwe],
                    "precision": "low",
                },
                "defaultConfiguration": {"level": "note"},
            }

        for rel_path in res.files:
            uri = rel_path
            if absolute_paths:
                uri = str((repo / rel_path).resolve())

            sarif_results.append({
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": (
                        f"{cwe}: fisier candidat, localizat de Antares "
                        f"({len(res.files)} fisiere returnate pentru acest CWE)."
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        # linia 1 e conventie: modelul nu produce linii
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "cwe": cwe,
                    "files_returned": len(res.files),
                    "tool_budget": res.tool_budget,
                    "duration_seconds": res.duration_seconds,
                },
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "antares",
                "informationUri": "https://huggingface.co/collections/fdtn-ai/antares",
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--hypotheses", type=Path,
                   default=_HERE / "hypotheses.txt")
    p.add_argument("--cwe", help="o singura ipoteza, ignora fisierul")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    p.add_argument("--force", action="store_true", help="ignora cache-ul")
    p.add_argument("--relative-paths", action="store_true",
                   help="emite cai relative in loc de absolute")
    args = p.parse_args()

    if not args.repo.exists():
        print(f"Repo inexistent: {args.repo}", file=sys.stderr)
        return 2

    if args.cwe:
        hypotheses = [args.cwe.upper()]
    elif args.hypotheses.exists():
        hypotheses = read_hypotheses(args.hypotheses)
    else:
        print(f"Lipseste {args.hypotheses}", file=sys.stderr)
        return 2

    if not hypotheses:
        print("Nicio ipoteza CWE de rulat.", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    print(f">> Antares pe {args.repo}")
    print(f"   {len(hypotheses)} ipoteze: {', '.join(hypotheses)}\n")

    results = []
    total_files = 0
    for i, cwe in enumerate(hypotheses, 1):
        try:
            res, cached = scan(args.repo, cwe,
                               cache_dir=args.cache_dir, force=args.force)
        except Exception as exc:  # noqa: BLE001
            print(f"   [{i}/{len(hypotheses)}] {cwe}: EROARE "
                  f"{type(exc).__name__}: {exc}")
            continue

        mark = "cache" if cached else f"{res.duration_seconds:.0f}s"
        if res.status == "error":
            print(f"   [{i}/{len(hypotheses)}] {cwe}: esuat "
                  f"({res.error_message})")
            continue

        print(f"   [{i}/{len(hypotheses)}] {cwe}: "
              f"{len(res.files)} fisiere  [{mark}]")
        for f in res.files[:5]:
            print(f"        {f}")
        results.append(res)
        total_files += len(res.files)

    doc = sarif_document(results, args.repo.resolve(),
                         absolute_paths=not args.relative_paths)
    out_path = args.out / "antares.sarif"
    out_path.write_text(json.dumps(doc, indent=2))

    print(f"\n   {total_files} findings din {len(results)} ipoteze "
          f"->  {out_path}")

    # nota onesta in consola: numarul de fisiere e semnal de incredere
    dropped = [r.cwe_id for r in results if len(r.files) > MAX_FILES]
    if dropped:
        print(f"   excluse ca dispersate (>{MAX_FILES} fisiere): "
              f"{', '.join(dropped)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
