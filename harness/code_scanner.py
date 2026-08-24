"""
Ramura B: wrapper peste `antares tool query`.

Scaneaza un repo pentru un CWE si returneaza fisierele candidate.
Rezultatele se pastreaza intr-un cache cu cheia (commit, cwe_id), pentru ca
o scanare dureaza zeci de secunde si nu se poate rula per alerta.

Utilizare:
    python3 code_scanner.py ~/soc-lab/target/app --cwe CWE-78
    python3 code_scanner.py ~/soc-lab/target/app --cwe CWE-78 --force
    python3 code_scanner.py ~/soc-lab/target/app --cwe CWE-78,CWE-89,CWE-22
    python3 code_scanner.py ~/soc-lab/target/app --cache-status
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CACHE = Path.home() / ".cache" / "soc-harness" / "code-scans"

# DECIZIE: buget 4, nu 15 (implicitul CLI-ului).
#
# Masurat pe 2026-08-21, 3 rulari per buget:
#   repo mic (2 MB, CWE-78):  buget 4 -> 15-16s, 3/3 acelasi fisier
#                             buget 15 -> 56-208s, 2/3 acelasi
#   repo mare (django 87 MB): buget 4 -> 54s
#                             buget 15 -> 696s, raspuns diferit si mai putin
#                                         plauzibil
#
# Traiectoriile arata repetitii de comenzi (tool_blocked: duplicate) si
# deriva dupa ce raspunsul a fost deja gasit. Mai mult buget = mai mult
# spatiu de ratacire, nu mai multa acoperire.
DEFAULT_TOOL_BUDGET = 4

DEFAULT_PROFILE = "local-llama"


@dataclass
class ScanResult:
    """Rezultatul unei scanari pentru un (repo, commit, CWE)."""

    repo_path: str
    repo_commit: str
    cwe_id: str

    files: list[str] = field(default_factory=list)
    finding_count: int = 0

    # provenienta -- necesara pentru raport si pentru reproducerea cifrelor
    scanned_at: str = ""
    duration_seconds: float = 0.0
    tool_budget: int = DEFAULT_TOOL_BUDGET
    profile: str = DEFAULT_PROFILE
    tool_call_count: int = 0
    failed_tool_calls: int = 0

    status: str = "ok"          # ok | error | empty
    error_message: str | None = None

    @property
    def has_surface(self) -> bool:
        """Exista cod care ar putea fi vulnerabil la acest CWE?"""
        return self.status == "ok" and bool(self.files)


def repo_commit(repo: Path) -> str:
    """
    Commit-ul curent al repo-ului. Face parte din cheia de cache, deci
    cache-ul se invalideaza automat cand se schimba codul.

    Daca nu e repo git, foloseste un hash al mtime-urilor -- mai fragil,
    dar suficient ca sa detecteze modificari.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()[:12]
    except (subprocess.SubprocessError, OSError):
        pass

    h = hashlib.sha256()
    for p in sorted(repo.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            h.update(f"{p}:{p.stat().st_mtime_ns}".encode())
    return "nogit-" + h.hexdigest()[:12]


def cache_key(commit: str, cwe_id: str) -> str:
    return f"{commit}__{cwe_id.replace('-', '_')}.json"


def read_cache(cache_dir: Path, commit: str, cwe_id: str) -> ScanResult | None:
    path = cache_dir / cache_key(commit, cwe_id)
    if not path.exists():
        return None
    try:
        return ScanResult(**json.loads(path.read_text()))
    except (json.JSONDecodeError, TypeError):
        return None          # cache corupt sau schema veche -> rescaneaza


def write_cache(cache_dir: Path, result: ScanResult) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / cache_key(result.repo_commit, result.cwe_id)
    path.write_text(json.dumps(asdict(result), indent=2))


def run_scan(
    repo: Path,
    cwe_id: str,
    *,
    profile: str = DEFAULT_PROFILE,
    tool_budget: int = DEFAULT_TOOL_BUDGET,
    timeout: int = 900,
) -> ScanResult:
    """
    Apeleaza `antares tool query --stdin`, care primeste JSON pe stdin si
    scrie JSON pe stdout.

    De ce interfata `tool` si nu `query`: iesirea e stabila si destinata
    consumului programatic. `antares query` randeaza carduri pentru om.
    """
    commit = repo_commit(repo)

    request = {
        "target": str(repo),
        "cwe_ids": [cwe_id],
        "profile": profile,
        "tool_budget": tool_budget,
    }

    result = ScanResult(
        repo_path=str(repo),
        repo_commit=commit,
        cwe_id=cwe_id,
        tool_budget=tool_budget,
        profile=profile,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["antares", "tool", "query", "--stdin"],
            input=json.dumps(request),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result.status = "error"
        result.error_message = f"timeout dupa {timeout}s"
        result.duration_seconds = time.monotonic() - started
        return result

    result.duration_seconds = round(time.monotonic() - started, 1)

    # Exit code 2 = invocare invalida sau esec de model. Findings singure
    # nu schimba exit code-ul, deci 0 si 1 sunt ambele rezultate valide.
    if proc.returncode == 2:
        result.status = "error"
        result.error_message = (proc.stderr or "")[:500]
        return result

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        result.status = "error"
        result.error_message = "iesire neparsabila: " + (proc.stdout or "")[:300]
        return result

    findings = payload.get("findings", [])
    result.files = [f.get("file_path") for f in findings if f.get("file_path")]
    result.finding_count = len(findings)

    summary = payload.get("summary", {}) or {}
    result.tool_call_count = summary.get("tool_call_count", 0)
    result.failed_tool_calls = summary.get("failed_tool_calls", 0)

    if not result.files:
        result.status = "empty"      # scanare reusita, dar fara suprafata

    return result


def scan(
    repo: Path,
    cwe_id: str,
    *,
    cache_dir: Path = DEFAULT_CACHE,
    force: bool = False,
    **kwargs,
) -> tuple[ScanResult, bool]:
    """
    Returneaza (rezultat, din_cache).

    Corelatorul apeleaza asta. In mod normal loveste cache-ul si raspunde
    instant; scanarea propriu-zisa ruleaza periodic sau la schimbarea codului.
    """
    commit = repo_commit(repo)

    if not force:
        cached = read_cache(cache_dir, commit, cwe_id)
        if cached is not None:
            return cached, True

    result = run_scan(repo, cwe_id, **kwargs)
    if result.status != "error":
        write_cache(cache_dir,result)
    return result, False


def cache_status(cache_dir: Path) -> None:
    if not cache_dir.exists():
        print(f"Cache gol: {cache_dir}")
        return
    entries = sorted(cache_dir.glob("*.json"))
    print(f"{len(entries)} scanari in cache ({cache_dir})")
    for p in entries:
        try:
            d = json.loads(p.read_text())
        except json.JSONDecodeError:
            print(f"  {p.name}  <corupt>")
            continue
        marker = "+" if d.get("files") else "-"
        print(
            f"  {marker} {d.get('cwe_id'):<10} {d.get('repo_commit'):<14} "
            f"{d.get('duration_seconds'):>6}s  {len(d.get('files', []))} fisiere"
        )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("repo", type=Path, nargs="?")
    p.add_argument("--cwe", help="CWE-78 sau lista: CWE-78,CWE-89")
    p.add_argument("--profile", default=DEFAULT_PROFILE)
    p.add_argument("--tool-budget", type=int, default=DEFAULT_TOOL_BUDGET)
    p.add_argument("--force", action="store_true", help="ignora cache-ul")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    p.add_argument("--cache-status", action="store_true")
    args = p.parse_args()

    if args.cache_status:
        cache_status(args.cache_dir)
        return 0

    if not args.repo or not args.cwe:
        p.error("repo si --cwe sunt necesare")

    if not args.repo.exists():
        print(f"Nu gasesc {args.repo}", file=sys.stderr)
        return 1

    commit = repo_commit(args.repo)
    print(f"repo   {args.repo}")
    print(f"commit {commit}")
    print()

    for cwe_id in [c.strip() for c in args.cwe.split(",") if c.strip()]:
        result, from_cache = scan(
            args.repo, cwe_id,
            cache_dir=args.cache_dir,
            force=args.force,
            profile=args.profile,
            tool_budget=args.tool_budget,
        )
        origin = "cache" if from_cache else f"scanat in {result.duration_seconds}s"
        print(f"{cwe_id}  [{result.status}]  ({origin})")
        if result.error_message:
            print(f"   eroare: {result.error_message}")
        for f in result.files:
            print(f"   -> {f}")
        if result.status == "empty":
            print("   -> nicio suprafata gasita")
        if result.tool_call_count:
            print(
                f"   apeluri: {result.tool_call_count} "
                f"({result.failed_tool_calls} esuate)"
            )
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
