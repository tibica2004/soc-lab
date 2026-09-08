#!/usr/bin/env python3
"""
known_findings.py — cauta in findings-urile deja indexate, in loc sa cheme modelul.

DE CE EXISTA: in `full_pipeline.py`, fiecare alerta detectata declanseaza o
scanare Antares. Chiar cu cache, modelul sta in calea critica a alertei.

Auditul periodic a facut deja munca. Findings-urile sunt in `soc-findings`.
Deci cand o alerta loveste `/admin/stats/disk`, intrebarea nu mai e "unde ar
putea fi vulnerabilitatea" ci "stim deja ca fisierul asta e vulnerabil?" --
si aia e o interogare, nu o inferenta.

Modelul iese din calea alertei si ramane in auditul periodic, unde
latenta lui nu conteaza.

CE NU FACE: nu inlocuieste scanarea. Daca alerta atinge o ruta pentru care
n-a rulat niciun audit, raspunsul e "necunoscut", nu "sigur". Necunoscutul
escaladeaza la om -- vezi conventia din correlate.decide().

    python3 known_findings.py --route /admin/stats/disk
    python3 known_findings.py --route /menu --cwe CWE-918
    python3 known_findings.py --stale-days 30
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

INDEX = "soc-findings"

# Cat de vechi poate fi un finding ca sa mai conteze. Un fisier reparat nu mai
# apare in rulari noi, deci `last_seen` ramane in urma. Pragul e o alegere,
# legata de cat de des ruleaza auditul -- nu o masuratoare.
DEFAULT_STALE_DAYS = 30


@dataclass
class KnownFinding:
    file: str
    cwes: list[str]
    tools: list[str]
    tier: int
    tier_label: str
    lines: list[int]
    last_seen: str
    messages: str = ""

    @property
    def corroborated(self) -> bool:
        """Confirmat de mai multe unelte independente."""
        return len(self.tools) > 1


@dataclass
class RouteMatch:
    route: str
    findings: list[KnownFinding] = field(default_factory=list)
    queried: bool = True

    @property
    def known_vulnerable(self) -> bool:
        return bool(self.findings)

    @property
    def best(self) -> KnownFinding | None:
        if not self.findings:
            return None
        return sorted(self.findings, key=lambda f: f.tier)[0]


def _request(es: str, path: str, body: dict, user: str, password: str,
             timeout: int = 15) -> dict:
    url = f"{es.rstrip('/')}/{path.lstrip('/')}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def route_tokens(route: str) -> list[str]:
    """
    Bucatile semnificative dintr-o ruta, pentru potrivirea cu caile de fisier.

    `/admin/stats/disk` -> ['admin', 'stats', 'disk']
    Segmentele numerice se arunca: `/menu/1` -> ['menu'], pentru ca id-ul nu
    apare in numele fisierului.
    """
    parts = [p for p in (route or "").strip("/").split("/") if p]
    return [p.lower() for p in parts if not p.isdigit()]


def lookup_route(route: str, *, es: str, user: str, password: str,
                 cwe: str | None = None,
                 stale_days: int = DEFAULT_STALE_DAYS) -> RouteMatch:
    """
    Findings cunoscute pentru fisierele care corespund unei rute.

    Potrivirea se face pe tokenii din ruta contra caii fisierului -- aceeasi
    logica ca `correlate.route_file_overlap`, dar executata in Elasticsearch.
    """
    match = RouteMatch(route=route)
    tokens = route_tokens(route)
    if not tokens:
        return match

    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=stale_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    should = [{"wildcard": {"file": {"value": f"*{t}*"}}} for t in tokens]
    query: dict = {
        "bool": {
            "should": should,
            "minimum_should_match": 1,
            "filter": [{"range": {"last_seen": {"gte": cutoff}}}],
        }
    }
    if cwe:
        query["bool"]["filter"].append({"term": {"cwes": cwe}})

    try:
        resp = _request(es, f"{INDEX}/_search", {
            "size": 20,
            "query": query,
            "sort": [{"tier": "asc"}],
        }, user, password)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            match.queried = False   # indexul nu exista: n-a rulat niciun audit
            return match
        raise
    except urllib.error.URLError:
        match.queried = False
        return match

    for hit in resp.get("hits", {}).get("hits", []):
        s = hit["_source"]
        match.findings.append(KnownFinding(
            file=s.get("file", ""),
            cwes=s.get("cwes", []),
            tools=s.get("tools", []),
            tier=s.get("tier", 9),
            tier_label=s.get("tier_label", ""),
            lines=s.get("lines", []),
            last_seen=s.get("last_seen", ""),
            messages=s.get("messages", ""),
        ))
    return match


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--es", default="http://192.168.56.10:9200")
    p.add_argument("--user", default="elastic")
    p.add_argument("--password", default="changeme123")
    p.add_argument("--route", help="ruta atacata")
    p.add_argument("--cwe", help="restrange la un CWE")
    p.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    p.add_argument("--all", action="store_true", help="tot indexul")
    a = p.parse_args()

    if a.all:
        try:
            resp = _request(a.es, f"{INDEX}/_search",
                            {"size": 50, "query": {"match_all": {}},
                             "sort": [{"tier": "asc"}]},
                            a.user, a.password)
        except urllib.error.URLError as exc:
            print(f"Elasticsearch inaccesibil: {exc.reason}", file=sys.stderr)
            return 1
        for h in resp.get("hits", {}).get("hits", []):
            s = h["_source"]
            print(f"  [{s.get('tier')}] {s.get('file')}  "
                  f"{','.join(s.get('cwes', []))}  "
                  f"{','.join(s.get('tools', []))}")
        return 0

    if not a.route:
        p.error("--route sau --all")

    m = lookup_route(a.route, es=a.es, user=a.user, password=a.password,
                     cwe=a.cwe, stale_days=a.stale_days)

    print(f"ruta:    {a.route}")
    print(f"tokeni:  {route_tokens(a.route)}")

    if not m.queried:
        print("rezultat: NECUNOSCUT (indexul lipseste sau ES inaccesibil)")
        print("          necunoscutul escaladeaza; nu inseamna 'sigur'.")
        return 0

    if not m.known_vulnerable:
        print("rezultat: niciun finding cunoscut pentru aceasta ruta")
        print("          nu inseamna ca e sigura -- doar ca auditul n-a gasit.")
        return 0

    print(f"rezultat: {len(m.findings)} findings cunoscute\n")
    for f in m.findings:
        mark = "confirmat de mai multe unelte" if f.corroborated else f.tier_label
        line = f" (linia {f.lines[0]})" if f.lines and f.lines[0] > 1 else ""
        print(f"  {f.file}{line}")
        print(f"      {', '.join(f.cwes)}  [{', '.join(f.tools)}]  {mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
