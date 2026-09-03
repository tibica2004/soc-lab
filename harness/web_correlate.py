"""
Ramura web, cap la cap: alerta Suricata -> CWE -> Antares -> verdict in cod.

Leaga piesele care existau deja separat:

    normalize_net.py   alerta ECS din Elasticsearch -> NetworkAlert
    signature_map.py   numele semnaturii -> CWE      (determinist)
    code_scanner.py    (repo, CWE) -> fisiere        (Antares, cu cache)
    correlate.py       semnalele -> prioritate       (determinist)

Ce NU face: nu cere modelului un verdict. Antares primeste repo si CWE si
intoarce o lista de fisiere -- sarcina lui declarata. Decizia "e sau nu o
tentativa care atinge cod vulnerabil" se ia in `correlate.decide()`, in cod.

Motivul e masurat, de trei ori: TNR 0.0 pe 30 de repouri patch-uite (O-013),
o singura abtinere din 95 pe faza A, si 24/24 verdicte identice pe alerte
indiferent de context (O-018). Intrebat "e vulnerabil?", modelul raspunde
mereu la fel. Deci nu e intrebat.

Utilizare:

    # din Elasticsearch, live
    python3 web_correlate.py --es http://192.168.56.10:9200 --password changeme123

    # dintr-un export salvat
    python3 web_correlate.py --from-file ../groundtruth/net_alerts.json

    # cu masurarea M2 fata de ground truth
    python3 web_correlate.py --from-file ... --truth ../groundtruth/web_runs.csv
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

from code_scanner import scan
from correlate import Correlation, best_overlap, decide
from normalize_net import NetworkAlert, load_network_alerts, normalize_network_alert
from signature_map import map_signature

ALERT_INDEX = "logs-suricata*"


# ---------------------------------------------------------------------------
# Sursa de alerte
# ---------------------------------------------------------------------------

def fetch_from_elastic(base_url: str, user: str, password: str,
                       size: int = 1000) -> list[NetworkAlert]:
    """Doar alertele, nu si evenimentele http/flow."""
    url = f"{base_url.rstrip('/')}/{ALERT_INDEX}/_search?size={size}"
    body = json.dumps({
        "query": {"term": {"suricata.eve.event_type": "alert"}},
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


# ---------------------------------------------------------------------------
# Corelarea unei alerte
# ---------------------------------------------------------------------------

def correlate_network_alert(alert: NetworkAlert, repo: Path,
                            cache_dir: Path) -> Correlation:
    """O alerta de retea -> o corelare cu starea codului."""
    cwe_id, cwe_label, _pattern = map_signature(alert.signature)

    c = Correlation(
        alert_uuid=alert.doc_id,
        timestamp=alert.timestamp,
        signature=alert.signature,
        route=alert.url_path,
        payload=alert.url_query,
        src_ip=alert.source_ip,
        cwe_id=cwe_id,
        cwe_label=cwe_label,
    )

    # Semnatura nemapata: nu stim ce sa cautam in cod. decide() trateaza.
    if cwe_id is None:
        return decide(c)

    try:
        result, from_cache = scan(repo, cwe_id, cache_dir=cache_dir)
    except Exception as exc:  # noqa: BLE001 -- statusul e rezultatul
        c.scan_status = "error"
        c.rationale.append(f"scanare esuata: {type(exc).__name__}: {exc}")
        return decide(c)

    c.scan_status = result.status
    c.candidate_files = list(result.files)
    c.file_count = len(result.files)
    c.has_surface = result.has_surface
    c.scan_from_cache = from_cache
    c.scan_duration = result.duration_seconds

    c.route_match, c.matched_file = best_overlap(alert.url_path, result.files)

    return decide(c)


# ---------------------------------------------------------------------------
# M2: masurarea fata de ground truth
# ---------------------------------------------------------------------------

def load_web_truth(path: Path) -> dict[str, dict[str, str]]:
    """web_runs.csv indexat pe request_id."""
    with path.open() as fh:
        return {row["request_id"]: row for row in csv.DictReader(fh)}


def measure_m2(alerts: list[NetworkAlert],
               correlations: list[Correlation],
               truth: dict[str, dict[str, str]]) -> list[str]:
    """
    A localizat Antares fisierul corect, pornind de la ruta atacata?

    Legatura alerta <-> rand de ground truth se face prin `request_id` din
    User-Agent, nu prin ferestre de timp. E determinista, si e simplificarea
    de laborator care evita toate ambiguitatile de etichetare de pe ramura
    de endpoint. In productie nu ai marcaj in cerere -- de consemnat.
    """
    lines: list[str] = []
    add = lines.append

    hit = miss = unmatched = 0
    rows: list[tuple[str, str, str, str, str]] = []

    for alert, c in zip(alerts, correlations):
        rid = alert.request_id
        if rid is None or rid not in truth:
            unmatched += 1
            continue

        row = truth[rid]
        expected = (row.get("expected_file") or "").strip()
        if not expected:
            # N2 si N3: nu exista fisier corect. Aici masuram altceva --
            # daca sistemul se abtine sa escaladeze. Nu intra in M2.
            continue

        found = expected in c.candidate_files
        hit += found
        miss += not found
        rows.append((rid, row.get("cwe", ""), expected,
                     "DA" if found else "nu", c.priority))

    add("## M2 — localizarea fisierului vulnerabil")
    add("")
    add("| cerere | CWE | fisier asteptat | localizat | prioritate |")
    add("|---|---|---|---|---|")
    for rid, cwe, expected, found, prio in rows:
        add(f"| {rid} | {cwe} | `{expected}` | {found} | {prio} |")
    add("")
    total = hit + miss
    if total:
        add(f"**{hit}/{total} localizate corect.**")
    else:
        add("Niciun caz pozitiv potrivit — verifica `request_id` in User-Agent.")
    if unmatched:
        add(f"({unmatched} alerte fara request_id, in afara masuratorii)")
    return lines


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--es", help="URL Elasticsearch")
    source.add_argument("--from-file", type=Path, help="export salvat")
    parser.add_argument("--user", default="elastic")
    parser.add_argument("--password", default="")
    parser.add_argument("--repo", type=Path, default=Path("../sample_repo"))
    parser.add_argument("--cache-dir", type=Path, default=Path("../.scan-cache"))
    parser.add_argument("--truth", type=Path, help="web_runs.csv, pentru M2")
    parser.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = parser.parse_args()

    if args.es:
        print(f"[1] Interoghez {args.es} ...")
        try:
            alerts = fetch_from_elastic(args.es, args.user, args.password)
        except Exception as exc:  # noqa: BLE001
            print(f"    esuat: {type(exc).__name__}: {exc}")
            return 1
    else:
        print(f"[1] Citesc {args.from_file} ...")
        alerts = load_network_alerts(args.from_file)

    print(f"    {len(alerts)} alerte de retea")
    with_route = [a for a in alerts if a.has_route]
    print(f"    {len(with_route)} cu ruta (corelabile cu codul)\n")

    if not args.repo.exists():
        print(f"EROARE: {args.repo} nu exista.")
        return 1

    print(f"[2] Corelez cu {args.repo} ...")
    correlations: list[Correlation] = []
    for i, alert in enumerate(alerts, 1):
        correlations.append(
            correlate_network_alert(alert, args.repo, args.cache_dir)
        )
        print(f"\r    {i}/{len(alerts)}", end="", flush=True)
    print("\n")

    # --- raport ------------------------------------------------------------
    lines: list[str] = []
    add = lines.append

    add("# Corelare alerta web — cod")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- sursa: {args.es or args.from_file}")
    add(f"- alerte: {len(alerts)} ({len(with_route)} cu ruta)")
    add(f"- repo: {args.repo}")
    add("")

    prio = Counter(c.priority for c in correlations)
    add("## Prioritati")
    add("")
    for p, n in prio.most_common():
        add(f"- {p}: {n}")
    add("")

    mapped = Counter(c.cwe_id or "nemapat" for c in correlations)
    add("## Mapare semnatura la CWE")
    add("")
    for cwe, n in mapped.most_common():
        add(f"- {cwe}: {n}")
    add("")

    scan_status = Counter(c.scan_status for c in correlations)
    add("## Statusuri de scanare")
    add("")
    for s, n in scan_status.most_common():
        add(f"- {s}: {n}")
    add("")

    if args.truth and args.truth.exists():
        lines.extend(measure_m2(alerts, correlations, load_web_truth(args.truth)))
        add("")

    add("## Escaladari")
    add("")
    for c in correlations:
        if c.priority in ("urgent", "high"):
            add(f"**{c.signature}** — `{c.route}`")
            add(f"- CWE: {c.cwe_id or 'nemapat'} | prioritate: {c.priority}")
            if c.matched_file:
                add(f"- fisier potrivit: `{c.matched_file}` "
                    f"(suprapunere {c.route_match:.2f})")
            for line in c.rationale:
                add(f"- {line}")
            add("")

    add("## Limitari")
    add("")
    add("- Antares localizeaza; verdictul se ia in `correlate.decide()`, in cod.")
    add("  Modelul nu e intrebat daca ceva e vulnerabil (O-013, O-018).")
    add("- Legatura alerta <-> ground truth prin `request_id` in User-Agent e o")
    add("  simplificare de laborator; in productie nu exista marcaj in cerere.")
    add("- File F1 0.305 pe benchmark: majoritatea fisierelor returnate sunt")
    add("  gresite. Potrivirea rutei filtreaza, dar nu repara localizarea.")
    add("- Prag de suprapunere 0.30, ales nu masurat.")

    report = "\n".join(lines) + "\n"
    print(report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-corelare-web.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
