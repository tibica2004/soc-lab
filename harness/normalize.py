"""
Stratul L1 al harness-ului: ingest + normalizare.

Citeste raspunsul brut de la Elasticsearch (_search pe indexul de alerte)
si produce obiecte NormalizedAlert. Nimic din straturile superioare
nu are voie sa vada alerta bruta -- doar acest model.

Utilizare:
    python3 normalize.py ~/soc-lab/groundtruth/alerts_raw.json
    python3 normalize.py ~/soc-lab/groundtruth/alerts_raw.json --out normalized.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Maparea regula -> clasa de alerta.
#
# Cheia este `kibana.alert.rule.rule_id` (UUID-ul stabil al regulii Elastic),
# NU `kibana.alert.rule.uuid` care se schimba la fiecare reinstalare.
#
# Se completeaza ruland normalize.py cu --unmapped, care listeaza regulile
# inca nemapate impreuna cu rule_id-ul lor.
# ---------------------------------------------------------------------------

AlertClass = Literal["cred_access", "persistence", "defense_evasion", "unmapped"]

RULE_CLASS_MAP: dict[str, AlertClass] = {
    # Se populeaza pe baza iesirii de la --unmapped.
    # Exemplu de forma:
    # "d0e159cf-73e9-40d1-a9ed-077e3158a855": "cred_access",
}

# Mapare de rezerva, pe nume de regula. Utila cat timp RULE_CLASS_MAP e goala,
# dar fragila (numele se pot schimba intre versiuni de pachet), deci este
# doar o punte pana se completeaza maparea pe rule_id.
RULE_NAME_CLASS_MAP: dict[str, AlertClass] = {
    "Potential Shadow File Read via Command Line Utilities": "cred_access",
    "Cron Job Created or Modified": "persistence",
    "Linux User Account Creation": "persistence",
    "Linux Group Creation": "persistence",
    "Tampering of Shell Command-Line History": "defense_evasion",
    "SUID/SGID Bit Set": "defense_evasion",
    "File Permission Modification in Writable Directory": "defense_evasion",
}


@dataclass
class NormalizedAlert:
    """Contractul de date pe care il vede tot restul harness-ului."""

    # identitate
    alert_uuid: str
    timestamp: str

    # regula care a produs alerta
    rule_id: str
    rule_uuid: str
    rule_name: str
    severity: str
    risk_score: int
    is_building_block: bool

    # ce s-a intamplat
    reason: str
    event_category: list[str] = field(default_factory=list)
    event_type: list[str] = field(default_factory=list)
    event_dataset: str | None = None
    event_outcome: str | None = None

    # cine / unde
    host_name: str | None = None
    host_id: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    process_parent_name: str | None = None

    # clasificare proprie
    alert_class: AlertClass = "unmapped"

    # diagnostic: ce context lipseste din alerta bruta
    missing_context: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Cheie de deduplicare folosita de pre-filtru (stratul L3)."""
        return "|".join(
            str(x)
            for x in (
                self.rule_id,
                self.host_id,
                self.user_name,
                self.process_name,
            )
        )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _first(value: Any) -> str | None:
    """Elastic returneaza uneori scalar, alteori lista cu un element."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def normalize_one(source: dict[str, Any]) -> NormalizedAlert:
    """Transforma un `_source` brut intr-un NormalizedAlert."""

    process = source.get("process") or {}
    parent = process.get("parent") or {}
    host = source.get("host") or {}
    user = source.get("user") or {}
    event = source.get("event") or {}

    alert = NormalizedAlert(
        alert_uuid=source.get("kibana.alert.uuid", ""),
        timestamp=source.get("@timestamp", ""),
        rule_id=source.get("kibana.alert.rule.rule_id", ""),
        rule_uuid=source.get("kibana.alert.rule.uuid", ""),
        rule_name=source.get("kibana.alert.rule.name", ""),
        severity=source.get("kibana.alert.severity", "unknown"),
        risk_score=int(source.get("kibana.alert.risk_score", 0) or 0),
        is_building_block="kibana.alert.building_block_type" in source,
        reason=source.get("kibana.alert.reason", ""),
        event_category=_as_list(event.get("category")),
        event_type=_as_list(event.get("type")),
        event_dataset=_first(event.get("dataset")),
        event_outcome=_first(event.get("outcome")),
        host_name=_first(host.get("hostname")) or _first(host.get("name")),
        host_id=_first(host.get("id")),
        user_name=_first(user.get("name")),
        process_name=_first(process.get("name")),
        process_command_line=_first(process.get("command_line")),
        process_parent_name=_first(parent.get("name")),
    )

    # Clasificare: intai pe rule_id (stabil), apoi pe nume (punte temporara).
    alert.alert_class = RULE_CLASS_MAP.get(
        alert.rule_id,
        RULE_NAME_CLASS_MAP.get(alert.rule_name, "unmapped"),
    )

    # Diagnostic: ce lipseste si va trebui cautat in telemetria bruta
    # de catre stratul de enrichment (L2). Alertele din system.auth
    # sunt mult mai sarace decat cele din endpoint.events.*.
    for name, value in (
        ("process.command_line", alert.process_command_line),
        ("process.parent.name", alert.process_parent_name),
        ("user.name", alert.user_name),
    ):
        if value is None:
            alert.missing_context.append(name)

    return alert


def load_alerts(path: Path) -> list[NormalizedAlert]:
    """Citeste un raspuns _search brut si returneaza alertele normalizate."""
    with path.open() as fh:
        payload = json.load(fh)

    hits = payload.get("hits", {}).get("hits", [])
    return [normalize_one(hit["_source"]) for hit in hits]


def report(alerts: list[NormalizedAlert], show_unmapped: bool = False) -> None:
    """Rezumat pe consola: distributii utile pentru decizii de design."""

    total = len(alerts)
    building_blocks = sum(1 for a in alerts if a.is_building_block)

    print(f"{total} alerte normalizate")
    print(f"{building_blocks} building block (candidat la excludere din triaj)")
    print()

    print("Pe clasa:")
    for cls, count in Counter(a.alert_class for a in alerts).most_common():
        print(f"  {count:>4}  {cls}")
    print()

    print("Pe dataset sursa:")
    for ds, count in Counter(a.event_dataset for a in alerts).most_common():
        print(f"  {count:>4}  {ds}")
    print()

    print("Context lipsa (cat va trebui recuperat prin enrichment):")
    missing = Counter()
    for a in alerts:
        for field_name in a.missing_context:
            missing[field_name] += 1
    for field_name, count in missing.most_common():
        pct = 100 * count / total if total else 0
        print(f"  {count:>4} ({pct:.0f}%)  {field_name}")
    print()

    print("Duplicate dupa fingerprint (cat ar taia dedup-ul din L3):")
    fps = Counter(a.fingerprint for a in alerts)
    unique = len(fps)
    print(f"  {total} alerte -> {unique} fingerprints unice")
    if total:
        print(f"  dedup ar elimina {total - unique} ({100*(total-unique)/total:.0f}%)")
    print()

    if show_unmapped:
        print("Reguli inca nemapate (adauga-le in RULE_CLASS_MAP):")
        seen: dict[str, str] = {}
        for a in alerts:
            if a.alert_class == "unmapped":
                seen[a.rule_id] = a.rule_name
        for rule_id, name in sorted(seen.items(), key=lambda kv: kv[1]):
            print(f'    "{rule_id}": "",  # {name}')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="alerts_raw.json de la Elasticsearch")
    parser.add_argument("--out", type=Path, help="scrie alertele normalizate ca JSON")
    parser.add_argument(
        "--unmapped",
        action="store_true",
        help="listeaza regulile nemapate, gata de lipit in RULE_CLASS_MAP",
    )
    args = parser.parse_args()

    if not args.path.exists():
        print(f"Nu gasesc {args.path}", file=sys.stderr)
        return 1

    alerts = load_alerts(args.path)
    report(alerts, show_unmapped=args.unmapped)

    if args.out:
        args.out.write_text(
            json.dumps([asdict(a) for a in alerts], indent=2, ensure_ascii=False)
        )
        print(f"Scris: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
