"""
Ablatie pe regulile arborelui de decizie.

Aceeasi metoda ca ablatia pe triagere din `ablation.py`, aplicata un strat mai
sus: scoti pe rand cate o regula si masori ce se pierde. O regula care nu
schimba nimic cand dispare e cod mort, iar una care taie mult zgomot dar
creste FN e o inrautatire deghizata in imbunatatire.

Extragerea se face O SINGURA DATA si se tine in memorie. Arborele e o functie
pura peste trasaturi, deci toate variantele se evalueaza instantaneu dupa
aceea. Cu extractorul de model asta inseamna 8 minute pentru intreaga tabela,
in loc de 8 minute per varianta.

Utilizare:

    python3 ablate_rules.py --alerts ../groundtruth/alerts_raw.json \\
                            --truth ../groundtruth/runs.csv \\
                            --extractor deterministic

    python3 ablate_rules.py ... --extractor model      # o trecere de ~8 min
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from ablation import label_alerts, load_ground_truth
from decide import Verdict, all_rule_ids, decide
from extract import Extractor
from extract_det import DeterministicExtractor
from normalize import load_alerts


def evaluate(cached, enabled, undetermined_escalates: bool) -> dict:
    """Ruleaza arborele peste trasaturi deja extrase. Fara model, fara I/O."""
    tp = tn = fp = fn = failed = 0
    fired: dict[str, int] = {}

    for alert, label, features in cached:
        if features is None:
            failed += 1
            continue
        decision = decide(features, alert, enabled_rules=enabled)
        fired[decision.fired_rule] = fired.get(decision.fired_rule, 0) + 1
        escalates = decision.escalates or (
            decision.verdict is Verdict.UNDETERMINED and undetermined_escalates
        )
        if label == "TP":
            tp += escalates
            fn += not escalates
        else:
            fp += escalates
            tn += not escalates

    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "failed": failed,
            "fired": fired}


def fmt(n: int, d: int) -> str:
    return "n/a" if d == 0 else f"{n / d * 100:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--extractor", default="deterministic",
                        choices=("model", "deterministic"))
    parser.add_argument("--undetermined", default="escalate",
                        choices=("escalate", "close"))
    parser.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = parser.parse_args()

    alerts = load_alerts(args.alerts)
    labelled = label_alerts(alerts, load_ground_truth(args.truth))
    extractor = (Extractor() if args.extractor == "model"
                 else DeterministicExtractor())

    print(f"[*] Extrag trasaturi pentru {len(labelled)} alerte "
          f"({args.extractor})...")
    cached = []
    for i, (alert, label) in enumerate(labelled, 1):
        result = extractor.extract(alert)
        cached.append((alert, label, result.features if result.ok else None))
        print(f"\r    {i}/{len(labelled)}", end="", flush=True)
    print("\n[*] Gata. Evaluez variantele de arbore.\n")

    escalate = args.undetermined == "escalate"
    rules = all_rule_ids()

    variants: list[tuple[str, list[str]]] = [("toate regulile", rules)]
    for rule_id in rules:
        variants.append((f"fara {rule_id}", [r for r in rules if r != rule_id]))
    variants.append(("niciuna (doar implicitul)", []))

    baseline = evaluate(cached, rules, escalate)
    n_tp = baseline["TP"] + baseline["FN"]
    n_fp = baseline["TN"] + baseline["FP"]

    lines: list[str] = []
    add = lines.append
    add("# Ablatie pe regulile arborelui de decizie")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- alerte: {args.alerts} ({len(labelled)} etichetate, "
        f"{n_tp} TP / {n_fp} FP)")
    add(f"- sursa trasaturilor: {args.extractor}")
    add(f"- UNDETERMINED contabilizat ca: {args.undetermined}")
    add("")
    add("Metoda: extragere o singura data, apoi arborele reevaluat pe fiecare")
    add("submultime de reguli. Coloana FN se citeste prima -- o varianta care")
    add("taie mai mult zgomot dar rateaza mai multe atacuri nu e o imbunatatire.")
    add("")
    add("| varianta | zgomot inchis | atacuri ratate | TNR | delta FN |")
    add("|---|---|---|---|---|")

    for name, enabled in variants:
        m = evaluate(cached, enabled, escalate)
        delta = m["FN"] - baseline["FN"]
        flag = "" if delta == 0 else (f" (+{delta})" if delta > 0 else f" ({delta})")
        add(f"| {name} | {m['TN']}/{n_fp} | {m['FN']}/{n_tp} | "
            f"{fmt(m['TN'], n_fp)} | {delta:+d}{flag and ''} |")

    add("")
    add("## Ce regula a decis, in varianta completa")
    add("")
    add("| regula | alerte decise |")
    add("|---|---|")
    for rule_id, count in sorted(baseline["fired"].items(),
                                 key=lambda kv: -kv[1]):
        add(f"| {rule_id} | {count} |")
    add("")
    dead = [r for r in rules if r not in baseline["fired"]]
    if dead:
        add(f"Reguli care nu s-au aprins niciodata: {', '.join(dead)}. "
            "Sunt cod mort pe setul asta -- fie conditia nu apare in date, "
            "fie o regula anterioara le fura mereu cazurile.")
        add("")

    add("## Limitari")
    add("")
    add(f"- {n_tp} pozitive. O diferenta de un singur FN muta rata cu "
        f"{100 / n_tp:.0f} de puncte, deci coloana FN e grosiera prin constructie.")
    if args.extractor == "deterministic":
        add("- extractorul determinist a fost scris dupa ce alertele au fost")
        add("  vazute; e o margine superioara pentru stratul de trasaturi, nu o")
        add("  solutie propusa.")
    add("- ablatia masoara contributia unei reguli DATE fiind celelalte;")
    add("  nu e o descompunere aditiva.")

    report = "\n".join(lines) + "\n"
    print(report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-ablatie-reguli-{args.extractor}.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
