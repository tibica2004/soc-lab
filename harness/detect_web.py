#!/usr/bin/env python3
"""
Detectie determinista pe evenimente HTTP, nu pe alertele Suricata.

M1 a masurat 1 din 6 atacuri detectate de semnaturile ET Open, pentru ca
acestea sunt legate de CVE-uri si produse specifice, nu de clase de atac.
Suricata scrie insa `event_type: http` pentru TOT traficul. Interogand acele
evenimente, toate cererile intra in sistem si detectia se muta in codul
propriu -- coerent cu restul arhitecturii.

LIMITARE: regulile sunt scrise DUPA ce s-au vazut payload-urile. Sunt optimist
partinitoare, ca extract_det.py. Comparatia cu ET Open e valida; nivelul
absolut nu se extrapoleaza.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

from normalize_net import NetworkAlert, normalize_network_alert


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    cwe: str
    pattern: str
    rationale: str

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text, flags=re.IGNORECASE) is not None


RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        "R1-path-traversal", "CWE-22",
        r"\.\./|\.\.%2f|%2e%2e|/etc/(passwd|shadow)|\bboot\.ini\b",
        "secvente de urcare in ierarhie sau cai de sistem in URI",
    ),
    DetectionRule(
        "R2-command-injection", "CWE-78",
        r"[;&|`]\s*(cat|ls|id|whoami|curl|wget|nc|sh|bash|echo)\b"
        r"|\$\(|&&\s*\w+|\|\|\s*\w+",
        "separator de comanda urmat de un binar uzual",
    ),
    DetectionRule(
        "R3-sqli-tautology", "CWE-89",
        r"'\s*or\s*'?\d*'?\s*=\s*'?\d|\bunion\s+(all\s+)?select\b"
        r"|\bor\s+1\s*=\s*1\b|--\s*$|;\s*drop\s+table",
        "tautologie, UNION SELECT sau comentariu terminal",
    ),
    DetectionRule(
        "R4-ssrf-internal", "CWE-918",
        r"(https?|file|gopher|dict)://(127\.|localhost|0\.0\.0\.0|169\.254\.|10\.|192\.168\.)",
        "URL catre o adresa interna intr-un parametru",
    ),
    DetectionRule(
        "R5-xss", "CWE-79",
        r"<script|javascript:|onerror\s*=|onload\s*=|%3cscript",
        "marcaj de script in parametri",
    ),
    DetectionRule(
        "R6-secrets-probe", "CWE-200",
        r"/\.(env|git|aws|ssh)|/wp-(admin|login|config)|/phpmyadmin"
        r"|/config\.(php|json|yml)",
        "cale cunoscuta de scanare pentru fisiere de configurare",
    ),
)


@dataclass
class Detection:
    alert: NetworkAlert
    rule_id: str | None
    cwe: str | None
    evidence: str

    @property
    def detected(self) -> bool:
        return self.rule_id is not None


def inspect(alert: NetworkAlert, enabled: tuple[DetectionRule, ...]) -> Detection:
    """Decodarea conteaza: %26%26echo e &&echo."""
    parts = [alert.url_path or "", alert.url_query or "", alert.url_original or ""]
    text = " ".join(unquote_plus(p) for p in parts if p)
    for rule in enabled:
        if rule.matches(text):
            return Detection(alert, rule.rule_id, rule.cwe, text[:120])
    return Detection(alert, None, None, text[:120])


def fetch_http_events(base: str, user: str, password: str,
                      minutes: int, size: int = 2000) -> list[NetworkAlert]:
    url = f"{base.rstrip('/')}/logs-suricata*/_search?size={size}"
    body = json.dumps({
        "query": {"bool": {"must": [
            {"term": {"suricata.eve.event_type": "http"}},
            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
        ]}},
        "sort": [{"@timestamp": "asc"}],
    }).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    return [normalize_network_alert(h)
            for h in payload.get("hits", {}).get("hits", [])]


def evaluate(events, truth, enabled) -> dict:
    tp = fn = fp = tn = 0
    fired = Counter()
    missed = []
    for ev in events:
        rid = ev.request_id
        if rid is None or rid not in truth:
            continue
        row = truth[rid]
        is_attack = row.get("label") == "ATTACK"
        d = inspect(ev, enabled)
        if d.detected:
            fired[d.rule_id] += 1
        if is_attack and d.detected:
            tp += 1
        elif is_attack:
            fn += 1
            missed.append((rid, row.get("payload_kind", "")))
        elif d.detected:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "fired": fired, "missed": missed}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--es", default="http://192.168.56.10:9200")
    p.add_argument("--user", default="elastic")
    p.add_argument("--password", default="")
    p.add_argument("--minutes", type=int, default=10)
    p.add_argument("--truth", type=Path,
                   default=Path("../groundtruth/web_runs.csv"))
    p.add_argument("--ablation", action="store_true")
    p.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = p.parse_args()

    print(f"[*] Evenimente HTTP din ultimele {args.minutes} minute...")
    events = fetch_http_events(args.es, args.user, args.password, args.minutes)
    with args.truth.open() as fh:
        truth = {r["request_id"]: r for r in csv.DictReader(fh)}
    matched = [e for e in events if e.request_id in truth]
    print(f"    {len(events)} evenimente, {len(matched)} legate de ground truth\n")
    if not matched:
        print("Nicio cerere identificata. Ruleaza attack_runner.py intai.")
        return 1

    variants = [("toate regulile", RULES)]
    if args.ablation:
        for r in RULES:
            variants.append((f"fara {r.rule_id}",
                             tuple(x for x in RULES if x is not r)))
        variants.append(("niciuna", ()))

    lines = []
    add = lines.append
    add("# Detectie determinista pe evenimente HTTP")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- evenimente: {len(events)}, dintre care {len(matched)} etichetate")
    add("")
    add("Interogheaza `event_type: http`, nu `alert`. Detectia se face in cod.")
    add("")
    add("| varianta | atacuri prinse | ratate | fals pozitive |")
    add("|---|---|---|---|")
    base = None
    for name, enabled in variants:
        m = evaluate(matched, truth, enabled)
        if base is None:
            base = m
        add(f"| {name} | {m['tp']}/{m['tp']+m['fn']} | {m['fn']} | "
            f"{m['fp']}/{m['fp']+m['tn']} |")
    add("")
    add("## Comparatie cu ET Open")
    add("")
    add(f"M1 pe acelasi trafic: 1 din 6. Determinist: {base['tp']} din "
        f"{base['tp']+base['fn']}.")
    add("")
    add("## Ce regula a prins ce")
    add("")
    for rid, n in base["fired"].most_common():
        add(f"- {rid}: {n}")
    dead = [r.rule_id for r in RULES if r.rule_id not in base["fired"]]
    if dead:
        add(f"\nReguli care nu s-au aprins: {', '.join(dead)}.")
    add("")
    if base["missed"]:
        add("## Atacuri ratate")
        add("")
        for rid, kind in base["missed"]:
            add(f"- {rid} ({kind})")
        add("")
    add("## Limitari")
    add("")
    add("- Regulile scrise DUPA ce s-au vazut payload-urile: optimist")
    add("  partinitoare, ca extract_det.py.")
    add("- Doar ruta si query string. Payload-urile din corpul cererii")
    add("  (w-002, w-003, w-005) nu sunt vizibile: Suricata nu logheaza corpul.")
    add("  Limitare de telemetrie, nu de reguli.")
    add("- Detectia prin tipare prinde ce seamana cu ce stii deja.")

    report = "\n".join(lines) + "\n"
    print(report)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-detectie-determinista.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
