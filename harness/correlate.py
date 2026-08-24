"""
Corelatorul -- piesa centrala a proiectului.

Combina ramura A (tentativa detectata in trafic) cu ramura B (suprafata
confirmata in cod) intr-un verdict cu prioritate.

Ipoteza testata: o tentativa de atac e mult mai urgenta daca exista cod
vulnerabil pentru acea clasa de slabiciune, pe ruta atacata. Nici IDS-ul
singur, nici scanerul de cod singur nu pot spune asta.

DECIZIE DE DESIGN CENTRALA: modelul nu decide nimic aici.
Antares a returnat o lista de fisiere. Tot ce urmeaza -- scorul, verdictul,
prioritatea -- e cod determinist, testabil unitar, explicabil la audit.

Utilizare:
    python3 correlate.py fixtures/synthetic_alerts.json --repo ~/soc-lab/target/app
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Literal

from signature_map import MappedAlert, load_and_map
from code_scanner import ScanResult, scan, DEFAULT_CACHE


Priority = Literal["urgent", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Semnalul 3: potrivirea rutei cu calea fisierului
#
# Observatie care a motivat aceasta euristica (2026-08-21):
#   alerta ataca  /api/admin/disk-stats
#   modelul gaseste  app/apis/admin/utils.py
# Ambele contin "admin". Nu e o coincidenta -- structura rutelor dintr-un
# API reflecta de obicei structura fisierelor.
#
# LIMITARE: functioneaza pe framework-uri cu rutare bazata pe structura de
# directoare (FastAPI, Django cu apps, Rails). Pe aplicatii cu rutare
# centralizata intr-un singur fisier, semnalul dispare. De testat, nu de
# presupus.
# ---------------------------------------------------------------------------

# Segmente prea generice ca sa insemne ceva daca se potrivesc.
STOPWORDS = {
    "api", "app", "src", "v1", "v2", "www", "static", "public",
    "index", "main", "utils", "services", "service", "routes", "handlers",
}


def path_tokens(text: str) -> set[str]:
    """Sparge o ruta sau o cale de fisier in segmente semnificative."""
    raw = re.split(r"[/\\._\-]+", text.lower())
    return {t for t in raw if len(t) > 2 and t not in STOPWORDS and not t.isdigit()}


def route_file_overlap(route: str | None, file_path: str) -> float:
    """
    Cat de mult se suprapun ruta atacata si calea fisierului gasit.

    Returneaza 0.0 - 1.0. Foloseste indicele Jaccard peste segmente,
    dupa eliminarea cuvintelor prea generice.
    """
    if not route:
        return 0.0
    a, b = path_tokens(route), path_tokens(file_path)
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a),len(b))


def best_overlap(route: str | None, files: list[str]) -> tuple[float, str | None]:
    """Cel mai bun scor de potrivire si fisierul care l-a produs."""
    best, best_file = 0.0, None
    for f in files:
        score = route_file_overlap(route, f)
        if score > best:
            best, best_file = score, f
    return best, best_file


# ---------------------------------------------------------------------------
# Verdictul
# ---------------------------------------------------------------------------


@dataclass
class Correlation:
    """O alerta de trafic, dupa ce a fost corelata cu starea codului."""

    alert_uuid: str
    timestamp: str
    signature: str
    route: str | None
    payload: str | None
    src_ip: str | None

    cwe_id: str | None
    cwe_label: str | None

    # ramura B
    scan_status: str = "not_run"     # ok | empty | error | not_run | unmapped
    candidate_files: list[str] = field(default_factory=list)
    scan_from_cache: bool = False
    scan_duration: float = 0.0

    # semnalele
    has_surface: bool = False        # 1: exista cod vulnerabil?
    file_count: int = 0              # 2: cate fisiere (putine = precis)
    route_match: float = 0.0         # 3: ruta se potriveste cu calea?
    matched_file: str | None = None

    # rezultatul
    priority: Priority = "info"
    rationale: list[str] = field(default_factory=list)


def decide(c: Correlation) -> Correlation:
    """
    Arborele de decizie. Determinist, fara model.

    Regula de baza: incertitudinea urca, nu coboara. Daca scanarea a esuat,
    nu stim nimic despre cod -- alerta isi pastreaza prioritatea proprie,
    nu e retrogradata.
    """
    r = c.rationale

    # Fara CWE mapat: alerta nu atinge codul. Triaj normal.
    if c.cwe_id is None:
        c.priority = "medium"
        r.append("semnatura nemapata la un CWE; fara scanare de cod")
        return c

    # Scanare esuata: NU stim daca exista suprafata. Nu retrograda.
    if c.scan_status == "error":
        c.priority = "high"
        r.append("scanarea de cod a esuat; incertitudine -> escaladare")
        return c

    # Scanare reusita, fara suprafata: probabil scan automat.
    if c.scan_status == "empty" or not c.has_surface:
        c.priority = "low"
        r.append(f"nicio suprafata gasita pentru {c.cwe_id}")
        r.append("tentativa fara cod vulnerabil corespunzator; probabil scan automat")
        return c

    # Exista suprafata. Cat de convingator?
    r.append(f"suprafata confirmata: {c.file_count} fisiere pentru {c.cwe_id}")

    if c.route_match >= 0.3:
        c.priority = "urgent"
        r.append(
            f"ruta atacata se potriveste cu {c.matched_file} "
            f"(suprapunere {c.route_match:.2f})"
        )
        r.append("tentativa tintita pe cod vulnerabil identificat")
        return c

    if c.file_count <= 2:
        c.priority = "high"
        r.append("localizare precisa, dar ruta nu se potriveste cu fisierele")
        return c

    c.priority = "medium"
    r.append(
        f"localizare dispersata ({c.file_count} fisiere); "
        "increderea in rezultat e scazuta"
    )
    return c


def correlate(
    alert: MappedAlert,
    repo: Path,
    *,
    cache_dir: Path = DEFAULT_CACHE,
    force: bool = False,
) -> Correlation:
    c = Correlation(
        alert_uuid=alert.alert_uuid,
        timestamp=alert.timestamp,
        signature=alert.signature,
        route=alert.route,
        payload=alert.payload,
        src_ip=alert.src_ip,
        cwe_id=alert.cwe_id,
        cwe_label=alert.cwe_label,
    )

    if alert.cwe_id is None:
        c.scan_status = "unmapped"
        return decide(c)

    # In mod normal loveste cache-ul si raspunde instant. Scanarea propriu-zisa
    # ruleaza periodic sau la schimbarea codului, nu per alerta.
    result, from_cache = scan(repo, alert.cwe_id, cache_dir=cache_dir, force=force)

    c.scan_status = result.status
    c.candidate_files = result.files
    c.scan_from_cache = from_cache
    c.scan_duration = result.duration_seconds
    c.has_surface = result.has_surface
    c.file_count = len(result.files)
    c.route_match, c.matched_file = best_overlap(alert.route, result.files)

    return decide(c)


# ---------------------------------------------------------------------------

PRIORITY_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def report(correlations: list[Correlation]) -> None:
    ordered = sorted(correlations, key=lambda c: PRIORITY_ORDER[c.priority])

    counts: dict[str, int] = {}
    for c in ordered:
        counts[c.priority] = counts.get(c.priority, 0) + 1

    print(f"{len(ordered)} alerte corelate")
    print("  " + "  ".join(f"{k}: {v}" for k, v in sorted(
        counts.items(), key=lambda kv: PRIORITY_ORDER[kv[0]]
    )))
    print()

    for c in ordered:
        print(f"[{c.priority.upper()}]  {c.alert_uuid}")
        print(f"    {c.signature}")
        print(f"    ruta     {c.route}")
        if c.payload:
            print(f"    payload  {c.payload}")
        if c.cwe_id:
            cache_note = " (din cache)" if c.scan_from_cache else ""
            print(f"    cod      {c.cwe_id} -> {c.scan_status}{cache_note}")
            for f in c.candidate_files:
                mark = "  <-- potrivire cu ruta" if f == c.matched_file and c.route_match >= 0.3 else ""
                print(f"             {f}{mark}")
        for line in c.rationale:
            print(f"    · {line}")
        print()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("alerts", type=Path, help="alerte (sintetice sau export real)")
    p.add_argument("--repo", type=Path, required=True, help="repo-ul aplicatiei tinta")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    p.add_argument("--force", action="store_true", help="rescaneaza, ignora cache-ul")
    p.add_argument("--out", type=Path, help="scrie corelatiile ca JSON")
    args = p.parse_args()

    for path in (args.alerts, args.repo):
        if not path.exists():
            print(f"Nu gasesc {path}", file=sys.stderr)
            return 1

    alerts = load_and_map(args.alerts)
    correlations = [
        correlate(a, args.repo, cache_dir=args.cache_dir, force=args.force)
        for a in alerts
    ]

    report(correlations)

    if args.out:
        args.out.write_text(
            json.dumps([asdict(c) for c in correlations], indent=2, ensure_ascii=False)
        )
        print(f"Scris: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
