"""
Conducta completa, cap la cap: Elasticsearch -> raport de analist.

Inlocuieste `hybrid_triage.py`, care avea trei defecte: nu rula dedup-ul (a
escaladat de patru ori aceeasi alerta de modul de kernel), inghitea tacut
iesirile goale ale modelului, si raporta un numar de alerte care nu se
potrivea cu suma categoriilor.

Etajele, in ordine:

    1. interogare live in Elasticsearch (sau fisier, cu --from-file)
    2. normalizare -> NormalizedAlert
    3. pre-filtru determinist: triage_prefilter_safe din ablation.py
       (masurat: 59% din zgomot inchis, 0/5 atacuri ratate)
    4. extragere de trasaturi -- determinista implicit, model optional
    5. arborele din decide.py
    6. raport pe categorii, cu motivul fiecarei escaladari

CE NU FACE ACEST SCRIPT: nu masoara nimic. Nu are ground truth, deci nu poate
spune daca a gresit. Cifrele pe care le tipareste sunt volume, nu performanta.
Pentru corectitudine exista `bench.py` si `ablate_rules.py`, care compara cu
etichete. Nu cita numere de aici intr-un raport.

Utilizare:

    python3 pipeline.py --es http://192.168.56.10:9200 --user elastic --password changeme123
    python3 pipeline.py --from-file ../groundtruth/alerts_raw.json
    python3 pipeline.py --from-file ... --extractor model --describe
"""

from __future__ import annotations

import argparse
import base64
import json
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from ablation import TRIAGERS
from decide import Verdict, decide
from extract import Extractor
from extract_det import DeterministicExtractor
from normalize import NormalizedAlert, normalize_one

ALERT_INDEX = ".alerts-security.alerts-default"


def fetch_from_elastic(base_url: str, user: str, password: str,
                       size: int, timeout: int = 30) -> list[dict]:
    """Interogheaza indexul de alerte. Doar citire."""
    url = f"{base_url.rstrip('/')}/{ALERT_INDEX}/_search?size={size}"
    body = json.dumps({
        "query": {"match_all": {}},
        "sort": [{"@timestamp": "asc"}],
    }).encode()

    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")

    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)

    hits = payload.get("hits", {}).get("hits", [])
    return [hit["_source"] for hit in hits]


def describe(extractor: Extractor, alert: NormalizedAlert) -> str:
    """
    Cere modelului o descriere in limbaj natural a comenzii.

    NU e un verdict si nu intra in nicio decizie. Masurat pe 2026-08-28:
    modelul produce text plauzibil cu erori de domeniu (a descris /etc/shadow
    ca backup al lui /etc/passwd, si /etc/passwd ca avand parole hash-uite).
    Se afiseaza marcat ca neverificat, pentru analist, nu ca justificare.
    """
    extractor.load()
    prompt = (
        "Describe what the following command line does on a Linux host. "
        "Two sentences maximum. Do not give a verdict.\n\n"
        f"{alert.process_command_line}"
    )
    try:
        response = extractor._llm.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0, max_tokens=160,
        )
    except Exception as exc:  # noqa: BLE001
        return f"[!] eroare de model: {type(exc).__name__}"

    text = (response["choices"][0]["message"]["content"] or "").strip()
    if not text:
        return "[!] modelul a intors iesire goala"
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--es", help="URL-ul Elasticsearch")
    source.add_argument("--from-file", type=Path, help="export salvat")
    parser.add_argument("--user", default="elastic")
    parser.add_argument("--password", default="")
    parser.add_argument("--size", type=int, default=2000)
    parser.add_argument("--prefilter", default="prefilter_safe",
                        choices=sorted(TRIAGERS))
    parser.add_argument("--extractor", default="deterministic",
                        choices=("model", "deterministic"))
    parser.add_argument("--describe", action="store_true",
                        help="cere modelului o descriere pentru escaladari")
    args = parser.parse_args()

    # --- 1-2. sursa si normalizare ---------------------------------------
    if args.es:
        print(f"[1] Interoghez {args.es} ...")
        try:
            sources = fetch_from_elastic(args.es, args.user, args.password,
                                         args.size)
        except urllib.error.HTTPError as exc:
            print(f"    Elasticsearch a raspuns {exc.code}: {exc.reason}")
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"    Nu am putut interoga: {type(exc).__name__}: {exc}")
            return 1
    else:
        print(f"[1] Citesc {args.from_file} ...")
        raw = json.loads(args.from_file.read_text())
        hits = raw.get("hits", {}).get("hits", raw) if isinstance(raw, dict) else raw
        sources = [h.get("_source", h) for h in hits]

    alerts = [normalize_one(s) for s in sources]
    print(f"    {len(alerts)} alerte brute\n")

    # --- 3. pre-filtru determinist ----------------------------------------
    verdicts = TRIAGERS[args.prefilter](alerts)
    survivors = [a for a, v in zip(alerts, verdicts) if v == "escalate"]
    closed_by_prefilter = len(alerts) - len(survivors)
    print(f"[2] Pre-filtru '{args.prefilter}': {closed_by_prefilter} inchise, "
          f"{len(survivors)} raman\n")

    # --- 4-5. trasaturi si arbore -----------------------------------------
    extractor = (Extractor() if args.extractor == "model"
                 else DeterministicExtractor())
    print(f"[3] Extrag trasaturi ({args.extractor}) si aplic arborele ...")

    decided: list[tuple[NormalizedAlert, Verdict, str]] = []
    failures = Counter()
    for i, alert in enumerate(survivors, 1):
        result = extractor.extract(alert)
        if not result.ok:
            failures[result.status] += 1
        decision = decide(result.features, alert)
        decided.append((alert, decision.verdict, decision.fired_rule))
        print(f"\r    {i}/{len(survivors)}", end="", flush=True)
    print("\n")

    # --- 6. raport ---------------------------------------------------------
    counts = Counter(v for _, v, _ in decided)
    escalated = [(a, r) for a, v, r in decided
                 if v in (Verdict.ACTIONABLE, Verdict.UNDETERMINED)]

    print("=" * 62)
    print("REZULTAT")
    print("=" * 62)
    print(f"  alerte brute                    {len(alerts)}")
    print(f"  inchise de pre-filtru           {closed_by_prefilter}")
    for verdict, count in counts.most_common():
        print(f"  {verdict.value:30s}  {count}")
    print(f"  {'-' * 34}")
    total = closed_by_prefilter + sum(counts.values())
    print(f"  total contabilizat              {total}"
          f"{'  <-- NEPOTRIVIRE' if total != len(alerts) else ''}")
    print(f"  ajung la analist                {len(escalated)}"
          f"  ({len(escalated) / len(alerts) * 100:.1f}% din brut)")
    if failures:
        print(f"\n  esecuri de extragere: {dict(failures)}")

    if escalated:
        print("\n" + "=" * 62)
        print("PENTRU ANALIST")
        print("=" * 62)
        for alert, rule in escalated:
            print(f"\n  {alert.rule_name}")
            print(f"    gazda: {alert.host_name}   utilizator: {alert.user_name}")
            print(f"    comanda: {alert.process_command_line or '<absenta>'}")
            print(f"    motiv: {rule}")
            if args.describe and alert.process_command_line:
                text = describe(
                    extractor if isinstance(extractor, Extractor) else Extractor(),
                    alert,
                )
                print(f"    descriere de model (NEVERIFICATA): {text}")

    print("\n[i] Volume, nu performanta. Pentru corectitudine: bench.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
