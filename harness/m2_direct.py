#!/usr/bin/env python3
"""
M2 direct: masoara STRICT localizarea, ocolind detectia.

De ce separat de web_correlate.py: sunt doua intrebari diferite.

    web_correlate.py:  lantul complet. Alerta Suricata -> CWE -> Antares.
                       Un caz ajunge la model doar daca Suricata l-a detectat
                       si semnatura s-a mapat. Pe setul curent, cele cinci
                       pozitive interesante nu trec de detectie, deci nu ajung
                       niciodata la punte.

    m2_direct.py:      hraneste corelatorul direct din web_runs.csv, cu ruta
                       si CWE-ul din ground truth. Forteaza toate cele sase
                       pozitive sa traverseze puntea. Raspunde la intrebarea
                       izolata: DACA un CWE real ajunge la Antares, localizeaza
                       fisierul corect?

Aceasta e M2 propriu-zisa. Rezultatul se compara cu predictia consemnata in
web_runs.csv INAINTE de rulare (reusita pe CWE-78 si 269, esec pe 862/639/200).

Nu foloseste Suricata. Nu inseamna ca detectia nu conteaza -- inseamna ca aici
masuram alt strat. Detectia are propria masuratoare (M1).

    python3 m2_direct.py
    python3 m2_direct.py --only-positives   # doar cazurile P, nu N2/N3
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path

from code_scanner import scan
from correlate import Correlation, best_overlap, decide


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path,
                        default=Path("../groundtruth/web_runs.csv"))
    parser.add_argument("--repo", type=Path, default=Path("../sample_repo"))
    parser.add_argument("--cache-dir", type=Path, default=Path("../.scan-cache"))
    parser.add_argument("--only-positives", action="store_true")
    parser.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = parser.parse_args()

    rows = list(csv.DictReader(args.csv.open()))

    # Doar randurile cu CWE si fisier asteptat pot masura localizarea.
    # N2 au CWE dar nu fisier (nu exista defect); N3 si benigne n-au nici CWE.
    testable = [
        r for r in rows
        if (r.get("cwe") or "").strip() and (r.get("expected_file") or "").strip()
    ]
    if args.only_positives:
        testable = [r for r in testable if r.get("case_type") == "P"]

    if not testable:
        print("Niciun rand testabil (cu CWE si expected_file).")
        return 1

    print(f"[*] {len(testable)} cazuri testabile, scanez {args.repo}\n")

    results: list[tuple[str, str, str, bool, int, float, str]] = []
    for row in testable:
        rid = row["request_id"]
        cwe = row["cwe"].strip()
        route = row["route"].strip()
        expected = row["expected_file"].strip()
        note = row.get("notes", "")

        try:
            scan_result, from_cache = scan(args.repo, cwe, cache_dir=args.cache_dir)
        except Exception as exc:  # noqa: BLE001
            results.append((rid, cwe, expected, False, 0, 0.0,
                            f"scanare esuata: {type(exc).__name__}"))
            print(f"  {rid} {cwe}: EROARE")
            continue

        found = expected in scan_result.files
        overlap, matched = best_overlap(route, scan_result.files)

        results.append((rid, cwe, expected, found,
                        len(scan_result.files), overlap,
                        "predictie: " + note.split("predictie")[-1][:60]
                        if "predictie" in note else ""))
        mark = "LOCALIZAT" if found else "ratat"
        cache = " (cache)" if from_cache else ""
        print(f"  {rid} {cwe}: {mark}  "
              f"[{len(scan_result.files)} fisiere, overlap {overlap:.2f}]{cache}")

    # --- raport ------------------------------------------------------------
    hit = sum(1 for r in results if r[3])
    total = len(results)

    lines: list[str] = []
    add = lines.append
    add("# M2 — localizarea vulnerabilitatii (direct, fara detectie)")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- repo: {args.repo}")
    add(f"- cazuri testabile: {total} (cu CWE si fisier asteptat)")
    add("")
    add("Corelatorul e hranit direct din web_runs.csv, ocolind Suricata.")
    add("Masoara strict: dat fiind CWE-ul corect, localizeaza Antares fisierul")
    add("vulnerabil? Detectia are masuratoare separata (M1).")
    add("")
    add("| cerere | CWE | fisier asteptat | localizat | fisiere | overlap |")
    add("|---|---|---|---|---|---|")
    for rid, cwe, expected, found, nfiles, overlap, _note in results:
        fname = expected.rsplit("/", 1)[-1]
        add(f"| {rid} | {cwe} | `{fname}` | "
            f"{'DA' if found else 'nu'} | {nfiles} | {overlap:.2f} |")
    add("")
    add(f"**{hit}/{total} localizate corect.**")
    add("")

    add("## Fata de predictia consemnata")
    add("")
    add("Predictia din web_runs.csv, scrisa inainte de rulare:")
    add("reusita pe CWE-78 si CWE-269, partiala pe CWE-918, esec pe")
    add("CWE-862, CWE-639, CWE-200 (defectul e absenta unei verificari, O-004).")
    add("")

    add("## Limitari")
    add("")
    add("- File F1 0.305 pe benchmark: rezultatul de aici e pe un singur repo")
    add("  mic, cu un caz per CWE. Confirma sau infirma predictia, nu produce")
    add("  o cifra generalizabila.")
    add("- 'localizat' inseamna ca fisierul corect e in lista returnata, nu ca")
    add("  e singurul. Numarul de fisiere spune cat de precisa e localizarea.")
    add("- Modelul nu da verdict; intoarce fisiere. Absenta suprafetei reale")
    add("  (N2) nu se testeaza aici -- vezi web_correlate.py.")

    report = "\n".join(lines) + "\n"
    print("\n" + report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-m2-localizare-directa.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
