"""
Benchmark extract-then-decide -- stratul de masurare.

Se leaga la SETUL NORMALIZAT, nu la CSV. CSV-ul ramane doar sursa de
etichete, prin `load_ground_truth` / `label_alerts`. Asta e reparatia
structurala: ramura extract-then-decide ocolise `normalize.py` si de aceea
rula pe 15 alerte toate TP, unde TN si FP erau imposibile prin constructie.
Pe setul normalizat sunt 105 negative si rezultatul se compune direct cu
baseline-ul deterministic `prefilter_safe` (62% zgomot taiat, FN 0).

Cerinta prealabila -- restaureaza harness-ul de ablatie:

    git show 2ef3d86:harness/evaluate.py > harness/ablation.py

Utilizare:

    python3 bench.py --alerts ../groundtruth/alerts_raw.json \\
                     --truth  ../groundtruth/runs.csv

    python3 bench.py --alerts ... --truth ... --gate       # poarta de dezacord
    python3 bench.py --alerts ... --truth ... --disable-rules R5-risk-threshold
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from ablation import label_alerts, load_ground_truth
from decide import Verdict, all_rule_ids, decide
from extract import Extractor
from extract_det import DeterministicExtractor
from features import FEATURE_FIELDS
from normalize import load_alerts


def git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        )
        sha = out.stdout.strip() or "necunoscut"
        return f"{sha}{'+modificari-necomise' if dirty.stdout.strip() else ''}"
    except Exception:  # noqa: BLE001
        return "necunoscut"


def rate(numerator: int, denominator: int, what: str) -> str:
    """
    O rata, sau motivul pentru care nu exista.

    Linia asta e tot ce trebuia ca sa nu apara "False Positive Rate 0.00%"
    intr-un raport pe un set fara niciun negativ.
    """
    if denominator == 0:
        return f"n/a (0 {what} in set)"
    return f"{numerator / denominator * 100:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0, help="0 = toate")
    parser.add_argument("--phrasing", default="a", choices=("a", "b"))
    parser.add_argument("--extractor", default="model",
                        choices=("model", "deterministic"),
                        help="sursa trasaturilor: modelul, sau regex (brat de control)")
    parser.add_argument("--gate", action="store_true",
                        help="poarta de dezacord (dubleaza timpul de rulare)")
    parser.add_argument("--gate-on", nargs="*", default=list(FEATURE_FIELDS))
    parser.add_argument("--disable-rules", nargs="*", default=[])
    parser.add_argument("--undetermined", default="escalate",
                        choices=("escalate", "close"),
                        help="cum se contabilizeaza UNDETERMINED in matrice")
    parser.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = parser.parse_args()

    alerts = load_alerts(args.alerts)
    windows = load_ground_truth(args.truth)
    labelled = label_alerts(alerts, windows)
    if args.limit:
        labelled = labelled[: args.limit]

    if not labelled:
        print("Nicio alerta etichetata. Verifica ferestrele din CSV.", file=sys.stderr)
        return 1

    label_dist = Counter(label for _, label in labelled)
    enabled = [r for r in all_rule_ids() if r not in set(args.disable_rules)]
    extractor = (
        Extractor() if args.extractor == "model" else DeterministicExtractor()
    )

    outcomes = Counter()
    verdicts = Counter()
    statuses = Counter()
    latencies: list[float] = []
    contingency: dict[str, dict[str, Counter]] = {
        f: defaultdict(Counter) for f in FEATURE_FIELDS
    }
    misses: list[tuple[str, str, str]] = []

    for index, (alert, label) in enumerate(labelled, start=1):
        if args.gate:
            left, _right, agreement = extractor.extract_twice(alert)
            result = left
        else:
            result = extractor.extract(alert, phrasing=args.phrasing)
            agreement = None

        statuses[result.status] += 1
        latencies.append(result.latency_s)

        decision = decide(
            result.features,
            alert,
            enabled_rules=enabled,
            agreement=agreement,
            require_agreement_on=args.gate_on if args.gate else (),
        )
        verdicts[decision.verdict.value] += 1

        if result.features is not None:
            for name in FEATURE_FIELDS:
                value = getattr(result.features, name).value
                contingency[name][value][label] += 1

        # A cincea categorie. Esecul de extragere nu se pierde in numitor.
        if not result.ok:
            outcomes["extraction_failed"] += 1
        else:
            escalates = decision.escalates or (
                decision.verdict is Verdict.UNDETERMINED
                and args.undetermined == "escalate"
            )
            if label == "TP" and escalates:
                outcomes["TP"] += 1
            elif label == "TP" and not escalates:
                outcomes["FN"] += 1
                misses.append((alert.rule_name, decision.fired_rule,
                               decision.verdict.value))
            elif label == "FP" and not escalates:
                outcomes["TN"] += 1
            else:
                outcomes["FP"] += 1

        print(f"\r[{index}/{len(labelled)}] {result.status:14s} "
              f"{decision.verdict.value:18s}", end="", flush=True)

    print()

    tp, tn = outcomes["TP"], outcomes["TN"]
    fp, fn = outcomes["FP"], outcomes["FN"]
    failed = outcomes["extraction_failed"]

    lines: list[str] = []
    add = lines.append

    add("# Benchmark extract-then-decide")
    add("")
    add("## Conditii de rulare")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- git: {git_sha()}")
    add(f"- alerte: {args.alerts} ({len(alerts)} brute, {len(labelled)} etichetate)")
    add(f"- ground truth: {args.truth}")
    add(f"- distributie etichete: TP={label_dist['TP']}  FP={label_dist['FP']}")
    add(f"- sursa trasaturilor: {args.extractor}")
    add(f"- model: {extractor.model_path}")
    add(f"- cuantizare: {extractor.quantization}")
    add(f"- temperature: {extractor.temperature}   n_ctx: {extractor.n_ctx}")
    add(f"- formulare: {'a+b (poarta activa)' if args.gate else args.phrasing}")
    add(f"- reguli active: {', '.join(enabled)}")
    if args.disable_rules:
        add(f"- reguli dezactivate: {', '.join(args.disable_rules)}")
    add(f"- UNDETERMINED contabilizat ca: {args.undetermined}")
    add("")

    add("## Rezultate")
    add("")
    add("| categorie | n |")
    add("|---|---|")
    add(f"| TP (atac escaladat) | {tp} |")
    add(f"| FN (atac inchis) | {fn} |")
    add(f"| TN (zgomot inchis) | {tn} |")
    add(f"| FP (zgomot escaladat) | {fp} |")
    add(f"| extragere esuata | {failed} |")
    add("")
    add(f"- TPR: {rate(tp, tp + fn, 'pozitive')}")
    add(f"- TNR: {rate(tn, tn + fp, 'negative')}")
    add(f"- FPR: {rate(fp, fp + tn, 'negative')}")
    add(f"- precizie: {rate(tp, tp + fp, 'escaladari')}")
    add(f"- rata de esec la extragere: "
        f"{rate(failed, len(labelled), 'alerte')}")
    if latencies:
        add(f"- latenta medie: {sum(latencies) / len(latencies):.2f}s "
            f"(total {sum(latencies) / 60:.1f} min)")
    add("")
    add("### Statusuri de extragere")
    for status, count in statuses.most_common():
        add(f"- {status}: {count}")
    add("")
    add("### Verdicte")
    for verdict, count in verdicts.most_common():
        add(f"- {verdict}: {count}")
    add("")

    add("## Tabele de contingenta pe trasatura")
    add("")
    add("Rezultatul central al etapei 1: care intrebari separa efectiv clasele.")
    add("O trasatura a carei distributie e aceeasi pe TP si pe FP nu poarta")
    add("semnal si trebuie scoasa din schema.")
    add("")
    for name in FEATURE_FIELDS:
        add(f"### {name}")
        add("")
        add("| valoare | TP | FP |")
        add("|---|---|---|")
        for value, counts in sorted(contingency[name].items()):
            add(f"| {value} | {counts['TP']} | {counts['FP']} |")
        add("")

    if misses:
        add("## Atacuri ratate")
        add("")
        add("| regula Elastic | regula care a decis | verdict |")
        add("|---|---|---|")
        for rule_name, fired, verdict in misses:
            add(f"| {rule_name} | {fired} | {verdict} |")
        add("")

    add("## Limitari")
    add("")
    add(f"- n={len(labelled)} dintr-un laborator cu un singur endpoint, "
        f"{label_dist['TP']} pozitive.")
    add("- o singura rulare per alerta; la temperature 0.0 extragerea e")
    add("  deterministica, dar asta nu spune nimic despre stabilitatea ei")
    add("  la reformulare -- pentru asta ruleaza cu --gate.")
    add("- pragul din R5 e o alegere, nu o masuratoare.")
    add("- rezultatul nu se extrapoleaza la productie.")

    report = "\n".join(lines) + "\n"
    print(report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = (args.results_dir /
           f"{stamp}-extract-then-decide-{args.extractor}-{args.alerts.stem}.md")
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
