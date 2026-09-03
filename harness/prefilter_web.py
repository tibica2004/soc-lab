#!/usr/bin/env python3
"""
Pre-filtru determinist pentru alerte de retea.

Acelasi rol ca `prefilter_safe` pe ramura de endpoint: taie zgomotul inainte
ca ceva scump sa fie chemat. Dar regulile sunt altele -- `fingerprint` pe
proces si `is_building_block` sunt concepte de endpoint care nu exista aici.

METODA e aceeasi si e cea care conteaza: triageri ca DATE, ablatie
leave-one-out, si coloana FN citita PRIMA. Un triager care taie mult zgomot
dar rateaza un atac nu e o imbunatatire.

Pragul: FN 0. Pe ramura de endpoint pragul era <2%, dar acolo aveai 5
pozitive; aici ai 6, deci un singur FN inseamna 17%. Cu esantionul asta,
singurul prag onest e zero.

    python3 prefilter_web.py --alerts ../groundtruth/net_alerts.json \\
                             --truth ../groundtruth/web_runs.csv --ablation
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path

from normalize_net import NetworkAlert, load_network_alerts, network_fingerprint

# ---------------------------------------------------------------------------
# Semnale
# ---------------------------------------------------------------------------

#: Cai pe care le cauta scanerele automate. Nu exista in aplicatie.
SCANNER_PATHS = (
    "/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
    "/phpmyadmin", "/pma", "/adminer",
    "/.env", "/.git", "/.svn", "/.aws",
    "/vendor/", "/cgi-bin/", "/shell", "/config.php",
    "/setup-config.php", "/administrator", "/solr", "/jenkins",
)

#: User agents de unelte de scanare. Un atacator serios le schimba, dar
#: majoritatea traficului automat nu.
SCANNER_AGENTS = (
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "nuclei",
    "dirbuster", "gobuster", "wpscan", "acunetix", "nessus",
)


def is_scanner_path(alert: NetworkAlert) -> bool:
    path = (alert.url_path or "").lower()
    return any(p in path for p in SCANNER_PATHS)


def is_scanner_agent(alert: NetworkAlert) -> bool:
    ua = (alert.user_agent or "").lower()
    return any(s in ua for s in SCANNER_AGENTS)


def hit_nothing(alert: NetworkAlert) -> bool:
    """
    Cererea nu a atins niciun handler: 404.

    Un atac catre o ruta inexistenta nu poate exploata cod care nu se executa.
    ATENTIE: nu inseamna ca atacatorul e inofensiv -- inseamna ca ACEASTA
    incercare a esuat. Un scan care produce sute de 404-uri ramane un semnal
    de urmarit la nivel de sursa, nu de alerta individuala.
    """
    return alert.http_status == 404


# ---------------------------------------------------------------------------
# Triageri
# ---------------------------------------------------------------------------

def triage_none(alerts: list[NetworkAlert]) -> list[str]:
    return ["escalate"] * len(alerts)


def triage_dedup(alerts: list[NetworkAlert]) -> list[str]:
    """Prima aparitie a unei amprente escaladeaza, repetarile se inchid."""
    seen: set[str] = set()
    out: list[str] = []
    for a in alerts:
        fp = network_fingerprint(a)
        out.append("auto_close" if fp in seen else "escalate")
        seen.add(fp)
    return out


def triage_scanner(alerts: list[NetworkAlert]) -> list[str]:
    """Cai si unelte de scanare cunoscute."""
    return ["auto_close" if (is_scanner_path(a) or is_scanner_agent(a))
            else "escalate" for a in alerts]


def triage_404(alerts: list[NetworkAlert]) -> list[str]:
    """Cereri care n-au atins niciun handler."""
    return ["auto_close" if hit_nothing(a) else "escalate" for a in alerts]


def _combine(*triagers):
    """Un triager compus: inchide daca ORICARE componenta ar inchide."""
    def combined(alerts: list[NetworkAlert]) -> list[str]:
        verdicts = [t(alerts) for t in triagers]
        return ["auto_close" if any(v[i] == "auto_close" for v in verdicts)
                else "escalate" for i in range(len(alerts))]
    return combined


def triage_prefilter_web(alerts: list[NetworkAlert]) -> list[str]:
    """Combinatia propusa: dedup + scanere. FARA 404."""
    return _combine(triage_dedup, triage_scanner)(alerts)


def triage_prefilter_web_aggressive(alerts: list[NetworkAlert]) -> list[str]:
    """Adauga si 404-urile. De masurat, nu de presupus ca e sigur."""
    return _combine(triage_dedup, triage_scanner, triage_404)(alerts)


def triage_all(alerts: list[NetworkAlert]) -> list[str]:
    return ["auto_close"] * len(alerts)


TRIAGERS = {
    "none": triage_none,
    "dedup": triage_dedup,
    "scanner": triage_scanner,
    "http_404": triage_404,
    "prefilter_web": triage_prefilter_web,
    "prefilter_web_aggressive": triage_prefilter_web_aggressive,
    "all": triage_all,
}


# ---------------------------------------------------------------------------
# Etichetare
# ---------------------------------------------------------------------------

def label_alerts(alerts: list[NetworkAlert],
                 truth: dict[str, dict[str, str]]) -> list[tuple[NetworkAlert, str]]:
    """
    Eticheteaza prin `request_id` din User-Agent, nu prin ferestre de timp.

    Un pozitiv (case_type P) e o alerta care NU trebuie inchisa automat.
    N2 si N3 sunt atacuri reale, dar fara cod vulnerabil corespunzator sau
    catre rute inexistente -- pot fi inchise fara sa se piarda un atac.
    """
    out = []
    for a in alerts:
        rid = a.request_id
        if rid is None or rid not in truth:
            continue
        out.append((a, truth[rid].get("case_type", "?")))
    return out


def evaluate(labelled, verdicts: list[str]) -> dict:
    closed_positives = sum(
        1 for (_, ct), v in zip(labelled, verdicts)
        if ct == "P" and v == "auto_close"
    )
    positives = sum(1 for _, ct in labelled if ct == "P")
    noise = sum(1 for _, ct in labelled if ct != "P")
    closed_noise = sum(
        1 for (_, ct), v in zip(labelled, verdicts)
        if ct != "P" and v == "auto_close"
    )
    return {
        "positives": positives,
        "noise": noise,
        "fn": closed_positives,
        "noise_cut": closed_noise,
        "auto_close": sum(1 for v in verdicts if v == "auto_close"),
        "total": len(verdicts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--ablation", action="store_true")
    parser.add_argument("--results-dir", type=Path, default=Path("../results"))
    args = parser.parse_args()

    alerts = load_network_alerts(args.alerts)
    with args.truth.open() as fh:
        truth = {r["request_id"]: r for r in csv.DictReader(fh)}

    labelled = label_alerts(alerts, truth)
    if not labelled:
        print("Nicio alerta etichetata. Verifica request_id in User-Agent.")
        return 1

    sub = [a for a, _ in labelled]
    dist = Counter(ct for _, ct in labelled)
    print(f"{len(alerts)} alerte incarcate, {len(labelled)} etichetate")
    print(f"tipuri: {dict(dist)}\n")

    names = list(TRIAGERS) if args.ablation else ["prefilter_web"]
    rows = []
    for name in names:
        m = evaluate(labelled, TRIAGERS[name](sub))
        rows.append((name, m))

    lines = []
    add = lines.append
    add("# Pre-filtru determinist pentru alerte de retea")
    add("")
    add(f"- data: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- alerte: {args.alerts} ({len(labelled)} etichetate)")
    add(f"- tipuri: {dict(dist)}")
    add("")
    add("Prag: FN 0. Cu 6 pozitive, un singur ratat inseamna 17% -- singurul")
    add("prag onest la esantionul asta e zero. Coloana FN se citeste prima.")
    add("")
    add("| triager | auto-close | zgomot taiat | FN |")
    add("|---|---|---|---|")
    for name, m in rows:
        noise_pct = (f"{m['noise_cut']}/{m['noise']}"
                     f" ({m['noise_cut'] / m['noise'] * 100:.0f}%)"
                     if m["noise"] else "n/a")
        flag = "" if m["fn"] == 0 else "  **peste prag**"
        add(f"| {name} | {m['auto_close']}/{m['total']} | {noise_pct} | "
            f"{m['fn']}/{m['positives']}{flag} |")
    add("")

    add("## Limitari")
    add("")
    add(f"- {dist.get('P', 0)} pozitive etichetate. Orice rata de FN e grosiera.")
    add("- Etichetarea prin request_id in User-Agent e o simplificare de")
    add("  laborator; in productie nu exista marcaj in cerere.")
    add("- `http_404` inchide cereri care n-au atins niciun handler. Nu")
    add("  inseamna ca sursa e inofensiva -- un scan cu sute de 404-uri ramane")
    add("  un semnal la nivel de IP, nu de alerta individuala.")
    add("- Listele de cai si unelte de scanare sunt scrise dupa ce s-au vazut")
    add("  datele. Pe trafic nou ar rata unelte necunoscute.")

    report = "\n".join(lines) + "\n"
    print(report)

    args.results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    out = args.results_dir / f"{stamp}-prefiltru-web.md"
    out.write_text(report)
    print(f"[i] Raport salvat: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
