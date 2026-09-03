#!/usr/bin/env python3
"""
Conducta completa a ramurii web, cap la cap.

Leaga cele trei straturi masurate separat pana acum:

    detect_web.py      evenimente HTTP -> detectie determinista -> CWE
    code_scanner.py    (repo, CWE) -> fisiere            (Antares localizeaza)
    correlate.py       potrivire ruta <-> cale -> verdict (cod determinist)

Diferenta fata de web_correlate.py: acolo CWE-ul venea din `signature_map`
aplicat semnaturii Suricata, deci un caz ajungea la model doar daca ET Open
il detectase. M1 a masurat 1 din 6. Aici CWE-ul vine din regulile proprii
aplicate traficului HTTP brut -- 7 din 12 detectate, zero fals pozitive.

Modelul nu e intrebat daca ceva e vulnerabil. Primeste repo si CWE, intoarce
fisiere. Verdictul se ia in cod, prin potrivirea rutei atacate cu calea
fisierului (O-006). Motivul e masurat: TNR 0.0 pe repouri patch-uite (O-013),
24/24 verdicte identice pe alerte (O-018).

    python3 full_pipeline.py --password changeme123 --minutes 10
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path

from code_scanner import scan
from correlate import Correlation, best_overlap, decide
from detect_web import RULES, fetch_http_events, inspect


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--es", default="http://192.168.56.10:9200")
    p.add_argument("--user", default="elastic")
    p.add_argument("--password", default="")
    p.add_argument("--minutes", type=int, default=10)
    p.add_argument("--repo", type=Path, default=Path("../sample_repo"))
    p.add_argument("--cache-dir", type=Path, default=Path("../.scan-cache"))
    p.add_argument("--truth", type=Path,
                   default=Path("../groundtruth/web_runs.csv"))
    p.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = p.parse_args()

    # --- 1. trafic ---------------------------------------------------------
    print(f"[1] Evenimente HTTP din ultimele {args.minutes} minute...")
    events = fetch_http_events(args.es, args.user, args.password, args.minutes)
    print(f"    {len(events)} evenimente\n")
    if not events:
        print("Niciun eveniment. Ruleaza attack_runner.py intai.")
        return 1

    truth = {}
    if args.truth.exists():
        with args.truth.open() as fh:
            truth = {r["request_id"]: r for r in csv.DictReader(fh)}

    # --- 2. detectie determinista -----------------------------------------
    print("[2] Detectie determinista...")
    detections = [inspect(e, RULES) for e in events]
    flagged = [d for d in detections if d.detected]
    print(f"    {len(flagged)} semnalate din {len(events)}\n")

    # --- 3-4. localizare si verdict ---------------------------------------
    print(f"[3] Corelez cu {args.repo}...")
    correlations: list[Correlation] = []
    for i, d in enumerate(flagged, 1):
        a = d.alert
        c = Correlation(
            alert_uuid=a.doc_id, timestamp=a.timestamp,
            signature=f"[determinist] {d.rule_id}",
            route=a.url_path, payload=a.url_query, src_ip=a.source_ip,
            cwe_id=d.cwe, cwe_label=d.cwe,
        )
        try:
            sr, cached = scan(args.repo, d.cwe, cache_dir=args.cache_dir)
            c.scan_status = sr.status
            c.candidate_files = list(sr.files)
            c.file_count = len(sr.files)
            c.has_surface = sr.has_surface
            c.scan_from_cache = cached
            c.route_match, c.matched_file = best_overlap(a.url_path, sr.files)
        except Exception as exc:  # noqa: BLE001
            c.scan_status = "error"
            c.rationale.append(f"scanare esuata: {type(exc).__name__}")
        correlations.append(decide(c))
        print(f"\r    {i}/{len(flagged)}", end="", flush=True)
    print("\n")

    # --- raport ------------------------------------------------------------
    lines: list[str] = []
    add = lines.append
    add("# Conducta completa: trafic -> detectie -> cod -> verdict")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- evenimente HTTP: {len(events)}")
    add(f"- semnalate de detectia determinista: {len(flagged)}")
    add(f"- repo: {args.repo}")
    add("")
    add("Detectia vine din regulile proprii pe trafic HTTP brut, nu din")
    add("semnaturile ET Open (M1: 1/6). Verdictul se ia in cod, nu in model.")
    add("")

    prio = Counter(c.priority for c in correlations)
    add("## Prioritati")
    add("")
    for k, n in prio.most_common():
        add(f"- {k}: {n}")
    add("")

    # cazuri care traverseaza TOT lantul
    complete = [
        (d, c) for d, c in zip(flagged, correlations)
        if c.priority == "urgent"
    ]
    add("## Cazuri care traverseaza tot lantul")
    add("")
    add("Detectat de stratul propriu, mapat la CWE, localizat de Antares,")
    add("si confirmat prin potrivirea rutei cu calea fisierului.")
    add("")
    if not complete:
        add("Niciunul.")
    else:
        add("| cerere | regula | CWE | fisier | overlap |")
        add("|---|---|---|---|---|")
        for d, c in complete:
            rid = d.alert.request_id or "-"
            add(f"| {rid} | {d.rule_id} | {c.cwe_id} | "
                f"`{c.matched_file}` | {c.route_match:.2f} |")
    add("")

    add("## Toate escaladarile")
    add("")
    for d, c in zip(flagged, correlations):
        if c.priority not in ("urgent", "high"):
            continue
        rid = d.alert.request_id or "-"
        ct = truth.get(rid, {}).get("case_type", "?")
        add(f"**{rid}** ({ct}) — `{c.route}` — {d.rule_id} — {c.priority}")
        if c.matched_file:
            add(f"- fisier: `{c.matched_file}` (overlap {c.route_match:.2f})")
        for line in c.rationale:
            add(f"- {line}")
        add("")

    add("## Limitari")
    add("")
    add("- Regulile de detectie sunt scrise dupa ce s-au vazut payload-urile.")
    add("  Optimist partinitoare, ca extract_det.py.")
    add("- Payload-urile din corpul cererii nu sunt vizibile: Suricata nu")
    add("  logheaza corpul. Trei atacuri din sase raman inaccesibile.")
    add("- Antares localizeaza 1 din 6 CWE-uri pe acest repo (M2).")
    add("  Un caz traverseaza lantul doar daca ambele straturi il prind.")
    add("- Prag de suprapunere 0.30, ales nu masurat.")

    report = "\n".join(lines) + "\n"
    print(report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-conducta-completa.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
