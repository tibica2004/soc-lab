"""
Testeaza efectul istoricului de regula asupra discriminarii modelului.

Intrebarea: adaugarea unei linii de context ("aceasta regula a produs 32
fals-pozitive din 33 revizuite") schimba verdictele modelului?

Elastic Security Labs a raportat 60% -> 92% corectitudine adaugand context
pre-adus, fara sa schimbe modelul. Acesta e testul echivalent, la scara mica,
cu un SLM local.

METODA: perechi construite din alerte REALE de laborator, nu scenarii scrise
de mana. Fiecare pereche foloseste aceeasi regula de detectie si difera doar
prin contextul alertei. Etichetele vin din ground truth (runs.csv).

Fiecare alerta se ruleaza de doua ori:
  A) fara istoric  -- doar descrierea alertei
  B) cu istoric    -- plus linia din history.py

Utilizare:
    python3 test_history_effect.py --n 3
    python3 test_history_effect.py --n 3 --list-only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from normalize import NormalizedAlert, load_alerts
from evaluate import load_ground_truth, parse_ts
from history import GroundTruthSource

ENDPOINT = "http://127.0.0.1:8000/v1/completions"
MODEL = "antares-1b"
SYSTEM = "You are a security analyst triaging SIEM alerts."
INSTRUCTION = (
    "Return ONLY a JSON object with fields: verdict (one of TP/FP), "
    "confidence (0-100), reason (max 20 words)."
)

TRUTH = Path.home() / "soc-lab/groundtruth/runs.csv"
ALERTS = Path.home() / "soc-lab/groundtruth/alerts_raw.json"


@dataclass
class LabelledAlert:
    alert: NormalizedAlert
    label: str  # "TP" sau "FP"

    def describe(self) -> str:
        """Alerta ca text, pentru prompt. Doar fapte, fara indicii de eticheta."""
        parts = [
            f"Alert: rule '{self.alert.rule_name}'.",
            f"Severity: {self.alert.severity}.",
        ]
        if self.alert.process_name:
            cmd = self.alert.process_command_line or self.alert.process_name
            parts.append(f"Process: {cmd}.")
        if self.alert.process_parent_name:
            parts.append(f"Parent process: {self.alert.process_parent_name}.")
        if self.alert.user_name:
            parts.append(f"User: {self.alert.user_name}.")
        if self.alert.host_name:
            parts.append(f"Host: {self.alert.host_name}.")
        if self.alert.event_dataset:
            parts.append(f"Source: {self.alert.event_dataset}.")
        return " ".join(parts)


def label_alerts(window_seconds: int = 300) -> list[LabelledAlert]:
    """Aceeasi logica de etichetare ca evaluate.py: fereastra SI regula."""
    windows = load_ground_truth(TRUTH, window_seconds)
    out = []
    for a in load_alerts(ALERTS):
        if not a.timestamp:
            continue
        ts = parse_ts(a.timestamp)
        matches = [w for w in windows if w.contains(ts)]
        if not matches:
            continue
        is_tp = any(
            w.label == "TP" and w.expected_rules and a.rule_name in w.expected_rules
            for w in matches
        )
        out.append(LabelledAlert(a, "TP" if is_tp else "FP"))
    return out


def build_pairs(labelled: list[LabelledAlert]) -> list[tuple[str, LabelledAlert, LabelledAlert]]:
    """
    Perechi (regula, alerta_FP, alerta_TP) din aceeasi regula.

    Doar regulile care au produs si zgomot, si atac real. Alea sunt cazurile
    unde regula singura nu poate decide -- exact ce trebuie sa discrimineze
    triajul.
    """
    by_rule: dict[str, dict[str, list[LabelledAlert]]] = defaultdict(
        lambda: {"TP": [], "FP": []}
    )
    for la in labelled:
        by_rule[la.alert.rule_name][la.label].append(la)

    pairs = []
    for rule, groups in sorted(by_rule.items()):
        if not (groups["TP"] and groups["FP"]):
            continue

        # Cauta o pereche cu descrieri DIFERITE.
        #
        # Masurat 2026-08-26: 3 din 5 perechi din laborator aveau descrieri
        # identice -- acelasi proces, aceeasi linie de comanda, acelasi user,
        # acelasi host. Diferenta de eticheta venea doar din fereastra de timp.
        # Cauza: testele Atomic si scriptul de zgomot au rulat pe acelasi host,
        # cu acelasi user, executand literalmente aceleasi actiuni.
        #
        # Un triager nu poate discrimina ce nu difera. A le include ar masura
        # zgomot, nu capacitate.
        found = None
        for fp in groups["FP"]:
            for tp in groups["TP"]:
                if fp.describe() != tp.describe():
                    found = (rule, fp, tp)
                    break
            if found:
                break

        if found:
            pairs.append(found)
        else:
            print(f"  [exclus] {rule}: FP si TP au descrieri identice",
                  file=sys.stderr)
    return pairs


def call_model(body: str, max_tokens: int = 250) -> str:
    prompt = (
        f"<|start_of_role|>system<|end_of_role|>{SYSTEM}<|end_of_text|>\n"
        f"<|start_of_role|>user<|end_of_role|>{body}\n\n{INSTRUCTION}<|end_of_text|>\n"
        f"<|start_of_role|>assistant<|end_of_role|>"
    )
    payload = json.dumps({
        "model": MODEL, "prompt": prompt, "max_tokens": max_tokens,
        "temperature": 0.3, "stop": ["<|end_of_text|>", "<|start_of_role|>"],
    }).encode()
    req = urllib.request.Request(
        ENDPOINT, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["choices"][0]["text"]


def parse_verdict(text: str) -> str | None:
    m = re.search(r"\{.*?\}", text, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    v = str(d.get("verdict", "")).upper()
    return v if v in ("TP", "FP") else None


def run(body: str, n: int) -> list[str | None]:
    return [parse_verdict(call_model(body)) for _ in range(n)]


def majority(verdicts: list[str | None], target: str) -> bool:
    ok = [v for v in verdicts if v]
    return bool(ok) and sum(1 for v in ok if v == target) > len(ok) / 2


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=3, help="repetari per conditie")
    p.add_argument("--list-only", action="store_true", help="doar arata perechile")
    args = p.parse_args()

    labelled = label_alerts()
    pairs = build_pairs(labelled)
    hist_src = GroundTruthSource(TRUTH, ALERTS)

    print(f"{len(labelled)} alerte etichetate, {len(pairs)} reguli cu si TP si FP\n")
    if not pairs:
        print("Nicio pereche. Regulile din laborator nu au produs si TP si FP.",
              file=sys.stderr)
        return 1

    for rule, fp, tp in pairs:
        h = hist_src.lookup(rule)
        print(f"--- {rule}")
        print(f"    istoric: {h.as_prompt_line()}")
        print(f"    FP: {fp.describe()[:110]}")
        print(f"    TP: {tp.describe()[:110]}")
        print()

    if args.list_only:
        return 0

    # ---- masuratoarea ----
    results = {"fara": [0, 0], "cu": [0, 0]}   # [corecte, total]
    discriminated = {"fara": 0, "cu": 0}

    for rule, fp, tp in pairs:
        h = hist_src.lookup(rule)
        print(f"=== {rule}")

        for cond in ("fara", "cu"):
            verdicts = {}
            for kind, la in (("FP", fp), ("TP", tp)):
                body = la.describe()
                if cond == "cu" and h.is_informative:
                    body += "\n\n" + h.as_prompt_line()
                vs = run(body, args.n)
                verdicts[kind] = vs
                correct = sum(1 for v in vs if v == kind)
                results[cond][0] += correct
                results[cond][1] += len(vs)
                shown = ",".join(v or "?" for v in vs)
                print(f"  [{cond:4}] {kind}: {correct}/{len(vs)}  ({shown})")

            if majority(verdicts["FP"], "FP") and majority(verdicts["TP"], "TP"):
                discriminated[cond] += 1
        print()

    print("=" * 62)
    for cond in ("fara", "cu"):
        c, t = results[cond]
        pct = 100 * c / t if t else 0
        print(f"{cond:5} istoric: {c}/{t} verdicte corecte ({pct:.0f}%)   "
              f"discriminare {discriminated[cond]}/{len(pairs)}")
    print()
    print("Interpretare: daca 'cu' bate 'fara', contextul pre-adus imbunatateste")
    print("triajul fara sa schimbe modelul. Cu putine perechi, diferenta poate fi")
    print("zgomot -- verifica marimea esantionului inainte de a raporta o cifra.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
