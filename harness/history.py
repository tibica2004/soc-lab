"""
Lookup determinist: istoricul verdictelor pe o regula de detectie.

Motivatia: Elastic Security Labs a raportat o crestere de la 60% la 92%
corectitudine pe triaj, FARA sa schimbe modelul -- doar adaugand context
pre-adus, dintre care istoricul verdictelor pe regula era o componenta.

Acest modul aduce acel semnal. Nu foloseste modelul; e o interogare.

DECIZIE DE DESIGN: sursa e abstractizata printr-un protocol. Acum citeste
din runs.csv (ground truth de laborator, folosit ca proxy pentru verdicte
de analist). Cand vin alertele reale cu workflow_status, se schimba doar
implementarea sursei, nu si consumatorii.

Utilizare:
    python3 history.py --truth ~/soc-lab/groundtruth/runs.csv \\
                       --alerts ~/soc-lab/groundtruth/alerts_raw.json
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from normalize import NormalizedAlert, load_alerts


@dataclass
class RuleHistory:
    """Ce s-a intamplat istoric cu alertele acestei reguli."""

    rule_name: str
    total: int = 0
    false_positive: int = 0
    true_positive: int = 0
    unlabelled: int = 0
    days: int = 30

    @property
    def labelled(self) -> int:
        return self.false_positive + self.true_positive

    @property
    def fp_ratio(self) -> float:
        """Cat de des a fost zgomot. None-safe: 0.0 daca nu exista etichete."""
        return self.false_positive / self.labelled if self.labelled else 0.0

    @property
    def is_informative(self) -> bool:
        """
        Merita pus in prompt?

        Sub 5 alerte etichetate, proportia nu inseamna nimic. A spune
        modelului "1 din 1 a fost fals-pozitiv" e mai rau decat a nu-i
        spune nimic -- sugereaza o certitudine inexistenta.
        """
        return self.labelled >= 5

    def as_prompt_line(self) -> str:
        """Formularea care intra in promptul modelului."""
        if not self.is_informative:
            return "Rule history: insufficient data."
        pct = round(100 * self.fp_ratio)
        return (
            f"Rule history (last {self.days} days): {self.total} alerts from this "
            f"rule, {self.labelled} reviewed by analysts, {self.false_positive} "
            f"closed as false positive ({pct}%)."
        )


class HistorySource(Protocol):
    """Contractul pe care il implementeaza orice sursa de verdicte."""

    def lookup(self, rule_name: str, days: int = 30) -> RuleHistory: ...


# ---------------------------------------------------------------------------
# Sursa 1: ground truth de laborator (runs.csv + alerts_raw.json)
#
# Reconstruieste verdicte plauzibile din ferestrele de ground truth, exact
# ca `evaluate.py`: o alerta e TP daca a cazut in fereastra unui test Atomic
# SI regula ei e printre cele asteptate. Restul e FP.
# ---------------------------------------------------------------------------


class GroundTruthSource:
    def __init__(self, truth_csv: Path, alerts_json: Path, window_seconds: int = 300):
        from evaluate import load_ground_truth, parse_ts

        self._parse_ts = parse_ts
        self.windows = load_ground_truth(truth_csv, window_seconds)
        self.alerts = load_alerts(alerts_json)
        self._index: dict[str, RuleHistory] = {}
        self._build()

    def _build(self) -> None:
        for alert in self.alerts:
            if not alert.timestamp or not alert.rule_name:
                continue

            hist = self._index.setdefault(
                alert.rule_name, RuleHistory(rule_name=alert.rule_name)
            )
            hist.total += 1

            ts = self._parse_ts(alert.timestamp)
            matches = [w for w in self.windows if w.contains(ts)]
            if not matches:
                hist.unlabelled += 1
                continue

            is_tp = any(
                w.label == "TP" and w.expected_rules and alert.rule_name in w.expected_rules
                for w in matches
            )
            if is_tp:
                hist.true_positive += 1
            else:
                hist.false_positive += 1

    def lookup(self, rule_name: str, days: int = 30) -> RuleHistory:
        h = self._index.get(rule_name)
        if h is None:
            return RuleHistory(rule_name=rule_name, days=days)
        h.days = days
        return h


# ---------------------------------------------------------------------------
# Sursa 2: Elastic real (pentru cand vin datele de productie)
#
# Aceeasi interfata. Interogheaza workflow_status pe indexul de alerte.
# Netestata inca -- nu exista verdicte de analist in laborator.
# ---------------------------------------------------------------------------


class ElasticSource:
    def __init__(
        self,
        base_url: str = "http://192.168.56.10:9200",
        user: str = "elastic",
        password: str = "changeme123",
        index: str = ".alerts-security.alerts-*",
    ):
        self.base_url = base_url.rstrip("/")
        self.index = index
        self._auth = base64.b64encode(f"{user}:{password}".encode()).decode()

    def _search(self, body: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}/{self.index}/_search",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {self._auth}",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def lookup(self, rule_name: str, days: int = 30) -> RuleHistory:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"kibana.alert.rule.name": rule_name}},
                        {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                    ]
                }
            },
            "aggs": {
                "by_status": {"terms": {"field": "kibana.alert.workflow_status"}}
            },
        }
        try:
            data = self._search(body)
        except Exception as exc:  # noqa: BLE001
            print(f"  eroare Elastic: {exc}", file=sys.stderr)
            return RuleHistory(rule_name=rule_name, days=days)

        buckets = {
            b["key"]: b["doc_count"]
            for b in data.get("aggregations", {}).get("by_status", {}).get("buckets", [])
        }
        total = data.get("hits", {}).get("total", {}).get("value", 0)

        # In Elastic, "closed" inseamna rezolvat de analist. Nu distinge
        # intre FP si TP fara un camp suplimentar (workflow_reason sau
        # un tag). Aproximare: closed = fals-pozitiv, care e adevarat in
        # majoritatea SOC-urilor dar TREBUIE verificat pe date reale.
        return RuleHistory(
            rule_name=rule_name,
            total=total,
            false_positive=buckets.get("closed", 0),
            true_positive=buckets.get("acknowledged", 0),
            unlabelled=buckets.get("open", 0),
            days=days,
        )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--truth", type=Path, help="runs.csv (sursa ground truth)")
    p.add_argument("--alerts", type=Path, help="alerts_raw.json")
    p.add_argument("--elastic", action="store_true", help="interogheaza Elastic in loc")
    p.add_argument("--rule", help="o singura regula, in loc de toate")
    args = p.parse_args()

    if args.elastic:
        src: HistorySource = ElasticSource()
        if not args.rule:
            print("--elastic necesita --rule", file=sys.stderr)
            return 1
        rules = [args.rule]
    else:
        if not (args.truth and args.alerts):
            p.error("fara --elastic, --truth si --alerts sunt necesare")
        src = GroundTruthSource(args.truth, args.alerts)
        rules = [args.rule] if args.rule else sorted(src._index)

    print(f"{len(rules)} reguli\n")
    informative = 0
    for name in rules:
        h = src.lookup(name)
        mark = "*" if h.is_informative else " "
        if h.is_informative:
            informative += 1
        print(
            f"{mark} {h.total:>4} alerte  {h.true_positive:>3} TP  "
            f"{h.false_positive:>3} FP  {h.unlabelled:>3} neetichetate  "
            f"fp={h.fp_ratio:.0%}  {name}"
        )

    print(f"\n{informative} reguli cu istoric informativ (>=5 etichetate)")
    print("Doar acelea intra in prompt; sub prag, proportia nu inseamna nimic.\n")

    for name in rules:
        h = src.lookup(name)
        if h.is_informative:
            print(f"  {name}")
            print(f"    -> {h.as_prompt_line()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
