#!/usr/bin/env python3
"""
push_findings.py — duce rezultatul auditului in Elasticsearch.

Findings-urile din `fused.json` devin documente in indexul `soc-findings`,
ca sa poata fi interogate din conducta de alerte. Cand o alerta Suricata
loveste o ruta, conducta verifica daca fisierul corespunzator e deja cunoscut
ca vulnerabil -- fara sa cheme modelul in calea alertei.

CE SCHIMBA fata de `full_pipeline.py`: acolo Antares e chemat la fiecare
alerta detectata. Aici scanarea s-a facut deja, periodic, iar corelarea devine
o interogare. Modelul iese din calea critica.

CICLUL DE VIATA AL UNUI FINDING, decizia care conteaza:
Documentele nu se sterg intre rulari. Fiecare primeste `run_id`, `first_seen`
si `last_seen`. Un finding reparat inceteaza sa mai apara in rulari noi, deci
`last_seen` ramane in urma -- si il poti filtra la interogare. Asa pastrezi
istoricul (cand a aparut, cand a disparut) in loc sa-l pierzi la reindexare.

    python3 push_findings.py --run runs/latest
    python3 push_findings.py --run runs/latest --es http://192.168.56.10:9200
    python3 push_findings.py --stats
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

INDEX = "soc-findings"

MAPPING = {
    "mappings": {
        "properties": {
            "finding_id": {"type": "keyword"},
            "run_id": {"type": "keyword"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "repo": {"type": "keyword"},
            "file": {"type": "keyword"},
            "cwes": {"type": "keyword"},
            "tools": {"type": "keyword"},
            "tier": {"type": "integer"},
            "tier_label": {"type": "keyword"},
            "lines": {"type": "integer"},
            "has_error_level": {"type": "boolean"},
            "is_new": {"type": "boolean"},
            "messages": {"type": "text"},
        }
    }
}


def request(es: str, path: str, method: str = "GET",
            body: dict | str | None = None, user: str = "elastic",
            password: str = "", timeout: int = 30):
    url = f"{es.rstrip('/')}/{path.lstrip('/')}"
    data = None
    if body is not None:
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw.strip() else {}


def finding_id(repo: str, file: str, cwes: list[str]) -> str:
    """
    Identificator stabil: acelasi fisier cu acelasi CWE da mereu acelasi id.

    Fara el, fiecare rulare ar crea documente noi si n-ai putea spune daca un
    finding e acelasi sau altul.
    """
    key = f"{repo}|{file}|{','.join(sorted(cwes))}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def ensure_index(es: str, user: str, password: str) -> None:
    try:
        request(es, INDEX, "HEAD", user=user, password=password)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        request(es, INDEX, "PUT", MAPPING, user, password)
        print(f"   index {INDEX} creat")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, default=Path("runs/latest"))
    p.add_argument("--es", default="http://192.168.56.10:9200")
    p.add_argument("--user", default="elastic")
    p.add_argument("--password", default="changeme123")
    p.add_argument("--stats", action="store_true",
                   help="ce e in index, fara sa indexeze nimic")
    args = p.parse_args()

    if args.stats:
        try:
            agg = request(args.es, f"{INDEX}/_search", "POST", {
                "size": 0,
                "aggs": {
                    "pe_cwe": {"terms": {"field": "cwes", "size": 20}},
                    "pe_tier": {"terms": {"field": "tier_label", "size": 10}},
                    "ultima": {"max": {"field": "last_seen"}},
                },
            }, args.user, args.password)
        except urllib.error.HTTPError as exc:
            print(f"index inaccesibil ({exc.code}). Ruleaza fara --stats intai.")
            return 1
        total = agg["hits"]["total"]["value"]
        print(f"{total} findings in {INDEX}")
        for b in agg["aggregations"]["pe_tier"]["buckets"]:
            print(f"  {b['doc_count']:4}  {b['key']}")
        print("\npe CWE:")
        for b in agg["aggregations"]["pe_cwe"]["buckets"]:
            print(f"  {b['doc_count']:4}  {b['key']}")
        return 0

    fused = args.run / "fused.json"
    if not fused.exists():
        print(f"Lipseste {fused}. Ruleaza audit.sh intai.", file=sys.stderr)
        return 1

    data = json.loads(fused.read_text())
    repo = data.get("repo", "")
    run_id = args.run.resolve().name
    now = data.get("generated_at") or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")

    ensure_index(args.es, args.user, args.password)

    lines: list[str] = []
    count = 0
    for f in data.get("findings", []):
        fid = finding_id(repo, f["file"], f.get("cwes", []))
        doc = {
            "finding_id": fid,
            "run_id": run_id,
            "last_seen": now,
            "repo": repo,
            "file": f["file"],
            "cwes": f.get("cwes", []),
            "tools": f.get("tools", []),
            "tier": f.get("tier"),
            "tier_label": f.get("tier_label"),
            "lines": [l for l in f.get("lines", []) if l],
            "has_error_level": f.get("has_error_level", False),
            "is_new": bool(f.get("is_new")),
            "messages": " | ".join(
                i.get("message", "") for i in f.get("items", [])[:3]
            )[:1000],
        }
        # first_seen se pune doar la creare; upsert-ul nu-l suprascrie
        lines.append(json.dumps({"update": {"_index": INDEX, "_id": fid}}))
        lines.append(json.dumps({
            "doc": doc,
            "upsert": {**doc, "first_seen": now},
        }))
        count += 1

    if not count:
        print("Niciun finding de indexat.")
        return 0

    payload = "\n".join(lines) + "\n"
    resp = request(args.es, "_bulk", "POST", payload, args.user, args.password)

    errors = [it for it in resp.get("items", [])
              if it.get("update", {}).get("error")]
    if errors:
        print(f"   {len(errors)} erori la indexare; prima: "
              f"{errors[0]['update']['error'].get('reason','')[:160]}")

    request(args.es, f"{INDEX}/_refresh", "POST",
            user=args.user, password=args.password)

    print(f"   {count - len(errors)} findings indexate in {INDEX} "
          f"(run {run_id})")
    print(f"   verifica:  python3 push_findings.py --stats")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
