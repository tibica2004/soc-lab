"""
Harness de evaluare -- stratul L9.

Se scrie INAINTE de sistem. Scopul lui este sa raspunda la o singura
intrebare: cate alerte inchide automat sistemul, si cate atacuri reale
rateaza facand asta.

Metrica dominanta este false negative rate. Un sistem care rateaza atacuri
e mai prost decat niciun sistem. Toate celelalte cifre se raporteaza
conditionat pe ea.

Utilizare:
    # baseline: nu inchide nimic (referinta minima)
    python3 evaluate.py --alerts alerts_raw.json --truth runs.csv

    # cu un triager anume
    python3 evaluate.py --alerts alerts_raw.json --truth runs.csv --triager dedup

    # ablatie: toate triagerele inregistrate, comparate
    python3 evaluate.py --alerts alerts_raw.json --truth runs.csv --ablation
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Literal

from normalize import NormalizedAlert, load_alerts

Verdict = Literal["auto_close", "escalate"]
Label = Literal["TP", "FP"]


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


@dataclass
class GroundTruthWindow:
    """
    O fereastra de timp in care stim ce s-a intamplat.

    Rulare Atomic -> TP. Interval de zgomot scriptat -> FP.
    Alertele din afara oricarei ferestre raman neetichetate si sunt
    excluse din calcul (nu ghicim).
    """

    start: datetime
    end: datetime
    label: Label
    technique_id: str
    expected_rules: frozenset[str] = frozenset()
    note: str = ""

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end


def parse_ts(value: str) -> datetime:
    """Accepta ISO 8601 cu sau fara timezone; normalizeaza la UTC-naive."""
    value = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is not None:
        dt = dt.astimezone(tz=None).replace(tzinfo=None)
    return dt


def load_ground_truth(
    path: Path,
    window_seconds: int = 180,
) -> list[GroundTruthWindow]:
    """
    Citeste runs.csv:
        timestamp_utc,technique_id,test_number,host,label,notes

    Fiecare rulare devine o fereastra [t, t + window_seconds].
    Pentru zgomotul scriptat, foloseste doua randuri: unul cu label FP
    la pornire si notes continand "start", altul la oprire cu "stop".
    """
    windows: list[GroundTruthWindow] = []
    noise_start: datetime | None = None

    with path.open() as fh:
        for row in csv.DictReader(fh):
            label = (row.get("label") or "").strip().upper()
            if label not in ("TP", "FP"):
                continue  # FAILED, sau randuri incomplete

            ts = parse_ts(row["timestamp_utc"])
            notes = (row.get("notes") or "").lower()
            technique = (row.get("technique_id") or "").strip()

            if "start" in notes:
                noise_start = ts
                continue
            if "stop" in notes and noise_start is not None:
                windows.append(
                    GroundTruthWindow(noise_start, ts, "FP", technique,
                                      frozenset(), row.get("notes", ""))
                )
                noise_start = None
                continue

            raw_rules = (row.get("expected_rules") or "").strip()
            rules = frozenset(x.strip() for x in raw_rules.split("|") if x.strip())
            windows.append(
                GroundTruthWindow(
                    ts,
                    ts + timedelta(seconds=window_seconds),
                    label,  # type: ignore[arg-type]
                    technique,
                    rules,
                    row.get("notes", ""),
                )
            )

    return windows


def label_alerts(
    alerts: list[NormalizedAlert],
    windows: list[GroundTruthWindow],
) -> list[tuple[NormalizedAlert, Label]]:
    """
    Eticheteaza alertele care cad intr-o fereastra cunoscuta.

    Regula de prioritate: daca o alerta cade si intr-o fereastra TP si
    intr-una FP, castiga TP. Altfel am putea marca un atac drept zgomot
    doar pentru ca scriptul rula in paralel.
    """
    labelled: list[tuple[NormalizedAlert, Label]] = []

    for alert in alerts:
        if not alert.timestamp:
            continue
        ts = parse_ts(alert.timestamp)
        matches = [w for w in windows if w.contains(ts)]
        if not matches:
            continue

        # TP cere fereastra SI regula asteptata. O alerta de discovery care
        # cade langa un test Atomic nu e adevarat-pozitiva pentru acel test.
        # Fara aceasta conditie, 7 tehnici produceau 65 "TP".
        is_tp = any(
            w.label == "TP" and w.expected_rules and alert.rule_name in w.expected_rules
            for w in matches
        )
        label: Label = "TP" if is_tp else "FP"
        labelled.append((alert, label))

    return labelled


# ---------------------------------------------------------------------------
# Triagere
#
# Un triager primeste alertele in ordine cronologica si returneaza un verdict
# pentru fiecare. Poate tine stare interna (istoric, contoare), pentru ca
# asa lucreaza si sistemul real.
# ---------------------------------------------------------------------------

Triager = Callable[[list[NormalizedAlert]], list[Verdict]]
TRIAGERS: dict[str, Triager] = {}


def triager(name: str) -> Callable[[Triager], Triager]:
    def wrap(fn: Triager) -> Triager:
        TRIAGERS[name] = fn
        return fn

    return wrap


@triager("none")
def triage_none(alerts: list[NormalizedAlert]) -> list[Verdict]:
    """Referinta minima: escaladeaza tot. FN rate = 0, auto-close = 0."""
    return ["escalate"] * len(alerts)


@triager("all")
def triage_all(alerts: list[NormalizedAlert]) -> list[Verdict]:
    """Referinta maxima: inchide tot. Auto-close = 100%, FN rate = catastrofal.
    Exista doar ca sa arate ca metrica de volum singura nu inseamna nimic."""
    return ["auto_close"] * len(alerts)


@triager("building_block")
def triage_building_block(alerts: list[NormalizedAlert]) -> list[Verdict]:
    """Inchide alertele building block (nu sunt destinate triajului uman)."""
    return ["auto_close" if a.is_building_block else "escalate" for a in alerts]


@triager("dedup")
def triage_dedup(alerts: list[NormalizedAlert]) -> list[Verdict]:
    """Primul dintr-un fingerprint escaladeaza; repetitiile se inchid."""
    seen: set[str] = set()
    out: list[Verdict] = []
    for a in alerts:
        if a.fingerprint in seen:
            out.append("auto_close")
        else:
            seen.add(a.fingerprint)
            out.append("escalate")
    return out


@triager("prefilter")
def triage_prefilter(alerts: list[NormalizedAlert]) -> list[Verdict]:
    """
    Pre-filtrul determinist, stratul L3.
    Deocamdata: building block + dedup. Se extinde in faza 3 cu
    allowlist, corelare cu istoricul si praguri de severitate.
    """
    seen: set[str] = set()
    out: list[Verdict] = []
    for a in alerts:
        if a.is_building_block:
            out.append("auto_close")
            continue
        if a.fingerprint in seen:
            out.append("auto_close")
            continue
        seen.add(a.fingerprint)
        out.append("escalate")
    return out


# ---------------------------------------------------------------------------
# Metrici
# ---------------------------------------------------------------------------


@dataclass
class Metrics:
    name: str
    total: int
    auto_closed: int
    escalated: int
    tp_total: int
    fp_total: int
    tp_closed: int  # FALS NEGATIV -- atac inchis automat
    fp_closed: int  # reducere corecta de volum
    tp_escalated: int
    fp_escalated: int  # zgomot ramas la analist

    @property
    def auto_close_rate(self) -> float:
        return 100 * self.auto_closed / self.total if self.total else 0.0

    @property
    def fn_rate(self) -> float:
        """% din atacurile reale inchise automat. Metrica dominanta."""
        return 100 * self.tp_closed / self.tp_total if self.tp_total else 0.0

    @property
    def noise_reduction(self) -> float:
        """% din zgomot eliminat corect."""
        return 100 * self.fp_closed / self.fp_total if self.fp_total else 0.0

    @property
    def passes(self) -> bool:
        """Pragul din specificatie: FN rate sub 2%."""
        return self.fn_rate < 2.0


def evaluate(
    name: str,
    labelled: list[tuple[NormalizedAlert, Label]],
    fn: Triager,
) -> Metrics:
    alerts = [a for a, _ in labelled]
    labels = [lbl for _, lbl in labelled]
    verdicts = fn(alerts)

    if len(verdicts) != len(alerts):
        raise ValueError(f"{name}: a returnat {len(verdicts)} verdicte pentru {len(alerts)} alerte")

    m = Metrics(
        name=name,
        total=len(alerts),
        auto_closed=sum(1 for v in verdicts if v == "auto_close"),
        escalated=sum(1 for v in verdicts if v == "escalate"),
        tp_total=sum(1 for l in labels if l == "TP"),
        fp_total=sum(1 for l in labels if l == "FP"),
        tp_closed=sum(1 for v, l in zip(verdicts, labels) if v == "auto_close" and l == "TP"),
        fp_closed=sum(1 for v, l in zip(verdicts, labels) if v == "auto_close" and l == "FP"),
        tp_escalated=sum(1 for v, l in zip(verdicts, labels) if v == "escalate" and l == "TP"),
        fp_escalated=sum(1 for v, l in zip(verdicts, labels) if v == "escalate" and l == "FP"),
    )
    return m


def print_metrics(m: Metrics) -> None:
    flag = "OK " if m.passes else "!! "
    print(f"--- {m.name}")
    print(f"    alerte etichetate     {m.total}  ({m.tp_total} TP / {m.fp_total} FP)")
    print(f"    auto-close            {m.auto_closed}  ({m.auto_close_rate:.0f}%)")
    print(f"    reducere de zgomot    {m.fp_closed}/{m.fp_total}  ({m.noise_reduction:.0f}%)")
    print(f"{flag}  FALSE NEGATIVE RATE   {m.tp_closed}/{m.tp_total}  ({m.fn_rate:.1f}%)   prag: <2%")
    print(f"    ramase la analist     {m.escalated}  ({m.fp_escalated} zgomot, {m.tp_escalated} reale)")
    print()


def print_table(rows: list[Metrics]) -> None:
    print(f"{'triager':<18} {'auto-close':>11} {'zgomot taiat':>13} {'FN rate':>9}  ")
    print("-" * 56)
    for m in rows:
        flag = "" if m.passes else "  <-- peste prag"
        print(
            f"{m.name:<18} {m.auto_close_rate:>10.0f}% {m.noise_reduction:>12.0f}% "
            f"{m.fn_rate:>8.1f}%{flag}"
        )
    print()
    print("Un triager care taie mult zgomot dar depaseste pragul de FN nu e o")
    print("imbunatatire. Compara intai coloana FN, apoi restul.")


# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--alerts", type=Path, required=True, help="alerts_raw.json")
    p.add_argument("--truth", type=Path, required=True, help="runs.csv")
    p.add_argument("--triager", default="prefilter", choices=sorted(TRIAGERS))
    p.add_argument("--ablation", action="store_true", help="ruleaza toate triagerele")
    p.add_argument("--window", type=int, default=180, help="secunde per fereastra Atomic")
    args = p.parse_args()

    for path in (args.alerts, args.truth):
        if not path.exists():
            print(f"Nu gasesc {path}", file=sys.stderr)
            return 1

    alerts = load_alerts(args.alerts)
    windows = load_ground_truth(args.truth, args.window)
    labelled = label_alerts(alerts, windows)

    print(f"{len(alerts)} alerte incarcate")
    print(f"{len(windows)} ferestre de ground truth")
    print(f"{len(labelled)} alerte etichetate ({len(alerts) - len(labelled)} in afara oricarei ferestre, ignorate)")
    print()

    if not labelled:
        print("Nicio alerta etichetata. Verifica timestamp-urile din runs.csv", file=sys.stderr)
        print("si fusul orar -- alertele Elastic sunt in UTC.", file=sys.stderr)
        return 1

    if args.ablation:
        order = ["none", "building_block", "dedup", "prefilter", "all"]
        rows = [evaluate(n, labelled, TRIAGERS[n]) for n in order if n in TRIAGERS]
        for m in rows:
            print_metrics(m)
        print_table(rows)
    else:
        print_metrics(evaluate(args.triager, labelled, TRIAGERS[args.triager]))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
