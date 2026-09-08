#!/usr/bin/env python3
"""
fuse.py — uneste findings-urile Semgrep si Antares intr-o singura coada de triaj.

Ce face, in ordine:
  1. Citeste oricate fisiere SARIF (Semgrep, Antares, orice alt scanner).
  2. Normalizeaza caile la relative fata de radacina repo-ului.
  3. Aplica baseline-ul (ce ai triat deja nu mai apare).
  4. Grupeaza pe FISIER si ranguieste dupa acordul dintre unelte.
  5. Scrie fused.json, fused.md si fused.sarif.

De ce grupam pe fisier: Antares raporteaza doar la nivel de fisier (nu da linii).
Ca sa poti compara marul cu marul, cobori si Semgrep la granularitate de fisier
pentru ranking — dar pastrezi liniile lui in detaliu, pentru ca acolo sta
valoarea lui practica.

Fara dependinte externe: doar stdlib.

Utilizare:
  ./fuse.py --repo /cale/spre/site --out ./run \
            --sarif semgrep=out/semgrep.sarif --sarif antares=out/merged.sarif \
            --baseline baseline.json
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)

# Rangurile de incredere. Mai mic = te uiti primul.
TIER_BOTH_SAME_CWE = 1  # ambele unelte, acelasi CWE  -> cel mai puternic semnal
TIER_BOTH_DIFF_CWE = 2  # ambele unelte, CWE diferit  -> fisierul merita atentie
TIER_SEMGREP_ONLY = 3   # doar Semgrep -> are linie exacta, precizie buna
TIER_ANTARES_ONLY = 4   # doar Antares -> doar fisier, cere verificare manuala

TIER_LABEL = {
    TIER_BOTH_SAME_CWE: "ambele unelte, acelasi CWE",
    TIER_BOTH_DIFF_CWE: "ambele unelte",
    TIER_SEMGREP_ONLY: "doar Semgrep (cu linie)",
    TIER_ANTARES_ONLY: "doar Antares (doar fisier)",
}


def cwes_in(value):
    """Extrage recursiv toate CWE-urile dintr-o valoare arbitrara."""
    found = set()
    if value is None:
        return found
    if isinstance(value, str):
        found.update("CWE-" + n for n in CWE_RE.findall(value))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            found |= cwes_in(v)
    elif isinstance(value, dict):
        for v in value.values():
            found |= cwes_in(v)
    return found


def norm_path(uri, repo_root):
    """Normalizeaza o cale SARIF la relativa fata de repo_root."""
    if not uri:
        return ""
    p = uri
    for prefix in ("file://", "file:"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    p = os.path.normpath(p)
    if os.path.isabs(p) and repo_root:
        try:
            rel = os.path.relpath(p, repo_root)
            if not rel.startswith(".."):
                p = rel
        except ValueError:
            pass
    return p.lstrip("./")


def load_sarif(path, tool_label, repo_root):
    """Extrage findings normalizate dintr-un fisier SARIF."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        print(f"   [!] lipseste: {path} (ignorat)", file=sys.stderr)
        return out
    except json.JSONDecodeError as e:
        print(f"   [!] SARIF invalid {path}: {e}", file=sys.stderr)
        return out

    for run in doc.get("runs", []) or []:
        tool = run.get("tool", {}) or {}
        driver = tool.get("driver", {}) or {}

        # Indexeaza regulile (driver + extensions) ca sa putem scoate CWE-ul.
        rules = {}
        for r in driver.get("rules", []) or []:
            if r.get("id"):
                rules[r["id"]] = r
        for ext in tool.get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                if r.get("id"):
                    rules.setdefault(r["id"], r)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or ""
            rule = rules.get(rule_id, {})
            msg = ((res.get("message") or {}).get("text") or "").strip()

            cwes = cwes_in(rule_id) | cwes_in(rule) | cwes_in(msg)

            level = res.get("level") or (
                (rule.get("defaultConfiguration") or {}).get("level")
            ) or "warning"

            locs = res.get("locations") or []
            if not locs:
                locs = [{}]

            for loc in locs:
                phys = loc.get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri") or ""
                region = phys.get("region") or {}
                out.append({
                    "tool": tool_label,
                    "file": norm_path(uri, repo_root),
                    "line": region.get("startLine"),
                    "rule_id": rule_id,
                    "cwes": sorted(cwes),
                    "message": msg[:300],
                    "level": level,
                })
    return out


def load_baseline(path):
    """
    baseline.json: [{"file_path": "...", "cwe": "CWE-89"}, ...]
    Foloseste "cwe": "*" ca sa suprimi un fisier intreg.
    """
    if not path or not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as e:
        print(f"   [!] baseline necitibil ({e}) — continui fara.", file=sys.stderr)
        return set()
    keys = set()
    for entry in data or []:
        fp = (entry.get("file_path") or "").lstrip("./")
        cwe = entry.get("cwe") or "*"
        if fp:
            keys.add((fp, cwe.upper()))
    return keys


def suppressed(finding, baseline):
    fp = finding["file"]
    if (fp, "*") in baseline:
        return True
    for cwe in finding["cwes"] or ["-"]:
        if (fp, cwe.upper()) in baseline:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Fuziune SARIF pentru triaj")
    ap.add_argument("--repo", required=True, help="radacina repo-ului tinta")
    ap.add_argument("--out", required=True, help="director de output")
    ap.add_argument("--sarif", action="append", default=[], metavar="ETICHETA=CALE",
                    help="poate fi repetat, ex: --sarif semgrep=out/semgrep.sarif")
    ap.add_argument("--baseline", default="baseline.json")
    args = ap.parse_args()

    repo_root = os.path.abspath(args.repo)
    os.makedirs(args.out, exist_ok=True)

    # --- 1. incarca toate sursele -------------------------------------------
    findings = []
    sources = []
    for spec in args.sarif:
        if "=" not in spec:
            print(f"--sarif asteapta ETICHETA=CALE, am primit: {spec}", file=sys.stderr)
            return 2
        label, path = spec.split("=", 1)
        got = load_sarif(path, label.strip(), repo_root)
        print(f"   {label}: {len(got)} findings")
        sources.append(label.strip())
        findings.extend(got)

    if not findings:
        print("Nicio sursa a produs findings. Verifica input-urile.")

    # --- 2. baseline ---------------------------------------------------------
    baseline = load_baseline(args.baseline)
    before = len(findings)
    findings = [f for f in findings if f["file"] and not suppressed(f, baseline)]
    print(f"   baseline: suprimate {before - len(findings)}, ramase {len(findings)}")

    # --- 3. grupare pe fisier ------------------------------------------------
    groups = defaultdict(lambda: {"tools": set(), "cwes": set(), "items": []})
    for f in findings:
        g = groups[f["file"]]
        g["tools"].add(f["tool"])
        g["cwes"].update(f["cwes"])
        g["items"].append(f)

    # --- 4. ranking ----------------------------------------------------------
    ranked = []
    for path, g in groups.items():
        tools = g["tools"]
        multi = len(tools) > 1

        if multi:
            per_tool = defaultdict(set)
            for it in g["items"]:
                per_tool[it["tool"]].update(it["cwes"])
            sets = [s for s in per_tool.values() if s]
            shared = set.intersection(*sets) if len(sets) > 1 else set()
            tier = TIER_BOTH_SAME_CWE if shared else TIER_BOTH_DIFF_CWE
        elif "semgrep" in tools:
            tier = TIER_SEMGREP_ONLY
            shared = set()
        else:
            tier = TIER_ANTARES_ONLY
            shared = set()

        lines = sorted({i["line"] for i in g["items"] if i["line"]})
        has_error = any(i["level"] == "error" for i in g["items"])

        ranked.append({
            "file": path,
            "tier": tier,
            "tier_label": TIER_LABEL[tier],
            "tools": sorted(tools),
            "cwes": sorted(g["cwes"]),
            "shared_cwes": sorted(shared),
            "lines": lines,
            "count": len(g["items"]),
            "has_error_level": has_error,
            "items": g["items"],
        })

    # tier crescator; in interiorul tier-ului: severitate, apoi nr. de findings
    ranked.sort(key=lambda r: (r["tier"], not r["has_error_level"], -r["count"], r["file"]))

    # --- 5. output -----------------------------------------------------------
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "generated_at": stamp,
        "repo": repo_root,
        "sources": sources,
        "baseline_entries": len(baseline),
        "total_files": len(ranked),
        "total_findings": len(findings),
        "findings": ranked,
    }
    with open(os.path.join(args.out, "fused.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    # SARIF unit, pentru tooling care consuma SARIF
    merged_runs = []
    for spec in args.sarif:
        _, path = spec.split("=", 1)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                merged_runs.extend(json.load(fh).get("runs", []) or [])
        except (OSError, json.JSONDecodeError):
            continue
    with open(os.path.join(args.out, "fused.sarif"), "w", encoding="utf-8") as fh:
        json.dump({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": merged_runs,
        }, fh, indent=2)

    # Raport de triaj
    lines_out = [
        f"# Coada de triaj — {stamp}",
        "",
        f"- Repo: `{repo_root}`",
        f"- Surse: {', '.join(sources) or '—'}",
        f"- Fisiere candidate: {len(ranked)}  (din {len(findings)} findings)",
        f"- Intrari in baseline: {len(baseline)}",
        "",
        "Ordinea e dupa acordul dintre unelte. Incepe de sus.",
        "",
    ]
    current_tier = None
    for r in ranked:
        if r["tier"] != current_tier:
            current_tier = r["tier"]
            lines_out += ["", f"## {r['tier_label']}", ""]
        loc = f" (linii {', '.join(map(str, r['lines'][:8]))})" if r["lines"] else ""
        cwe = ", ".join(r["cwes"]) or "—"
        lines_out.append(f"- **`{r['file']}`**{loc} — {cwe}  _[{', '.join(r['tools'])}]_")
        for it in r["items"][:3]:
            if it["message"]:
                lines_out.append(f"    - {it['tool']}: {it['message'][:160]}")
    lines_out += [
        "",
        "---",
        "",
        "Dupa triaj, adauga in `baseline.json` ce ai reparat sau ce e fals-pozitiv:",
        '`[{"file_path": "cale/fisier.php", "cwe": "CWE-89"}]`  — foloseste `"*"` pentru tot fisierul.',
    ]
    with open(os.path.join(args.out, "fused.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines_out) + "\n")

    print(f"\n   {len(ranked)} fisiere candidate -> {args.out}/fused.md")
    both = sum(1 for r in ranked if r["tier"] <= TIER_BOTH_DIFF_CWE)
    if both:
        print(f"   {both} confirmate de ambele unelte — incepe cu alea.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
