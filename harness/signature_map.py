"""
Puntea dintre ramura A(trafic) si ramura B(cod).
O alerta de retea spune "cineva a incercat SQL injection".
Antares are nevoie de "CWE-89".Aceasta traducere trebuie sa fie determinista si auditabila -- nu o ghicire a modelului.

Utilizare: python3 signature_map.py fixtures/synthetic_alerts.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


#Mapare semnatura -> CWE

#DECIZIE DE DESIGN: maparea e MANUALA si INCOMPLETA, nu deriva automat.

#De ce nu automat:semnaturile ET au clasificari (web-application-attack)
#si uneori referinte CVEm dar nu CWE direct. Tagurile MITRE ATT&CK din
#regulile Elastic descriu cum ataca cineva(tehnica), nu ce e defect in cod
#(slabiciunea). Sunt taxonomii diferite; maparea intre ele e aproximativa.
#O regula etichetata T1190 "Exploit- Public-Facing Application" nu-ti spune
#ce CWE sa cauti.
#
#Ce nu e in tabel nu declanseaza scanare de cod. Nemapat = decizie explicita, nu omisiune.
#
#Cheia e un fragment din numele semnaturii, cautat case-insensitive.
#Ordinea conteaza: prima potrivire castiga. Pune tiparele specifice
#inaintea celor generale. 


SIGNATURE_CWE_RULES: list[tuple[str,str,str]]=[
	("sql injection",           "CWE-89",  "SQL Injection"),
	("sqli",		    "CWE-89",  "SQL Injection"),
	("command injection",       "CWE-78",  "OS Command Injection"),
    	("os command",              "CWE-78",  "OS Command Injection"),
   	("shell injection",         "CWE-78",  "OS Command Injection"),
   	("directory traversal",     "CWE-22",  "Path Traversal"),
    	("path traversal",          "CWE-22",  "Path Traversal"),
    	("cross site scripting",    "CWE-79",  "Cross-site Scripting"),
    	("xss",                     "CWE-79",  "Cross-site Scripting"),
    	("remote file inclusion",   "CWE-98",  "Remote File Inclusion"),
    	("local file inclusion",    "CWE-22",  "Path Traversal"),
    	("server side request",     "CWE-918", "SSRF"),
    	("ssrf",                    "CWE-918", "SSRF"),
    	("xml external entity",     "CWE-611", "XXE"),
    	("xxe",                     "CWE-611", "XXE"),
    	("deserialization",         "CWE-502", "Unsafe Deserialization"),
    	("code injection",          "CWE-94",  "Code Injection"),
    	("ldap injection",          "CWE-90",  "LDAP Injection"),
        ("/etc/passwd",             "CWE-22",  "Path Traversal"),
        ("file inclusion",          "CWE-98",  "Remote File Inclusion"),
]
# ---------------------------------------------------------------------------
# Extragerea rutei aplicative
#
# DECIZIE DE DESIGN: ruta e separata de query string.
#
# De ce: ruta (/api/admin/disk-stats) e ce vrei sa legi de un fisier din cod.
# Query string-ul (?path=;cat /etc/passwd) e payload-ul atacului -- util
# pentru triaj, dar nu pentru localizare.
#
# ATENTIE la Suricata: alerta de semnatura NU contine URL-ul. Contine IP,
# port si flow_id. URL-ul e intr-un eveniment HTTP separat, care trebuie
# corelat dupa flow_id. In fixture-urile sintetice l-am pus direct, ca sa
# putem construi restul; la integrarea reala e o piesa in plus.
# ---------------------------------------------------------------------------


@dataclass
class MappedAlert:
    """O alerta de trafic, dupa ce a fost legata (sau nu) de un CWE."""
 
    alert_uuid: str
    timestamp: str
    signature: str
    severity: str
 
    # rezultatul maparii
    cwe_id: str | None          # None = nu declanseaza scanare de cod
    cwe_label: str | None
    matched_pattern: str | None  # ce tipar a produs potrivirea (auditabilitate)
 
    # context de atac
    src_ip: str | None = None
    route: str | None = None     # calea, fara query string
    payload: str | None = None   # query string-ul, adica tentativa propriu-zisa
    http_method: str | None = None
 
    @property
    def triggers_code_scan(self) -> bool:
        return self.cwe_id is not None
 
 
def split_url(url: str | None) -> tuple[str | None, str | None]:
    """Separa ruta de query string."""
    if not url:
        return None, None
    if "?" in url:
        route, payload = url.split("?", 1)
        return route, payload
    return url, None
 
 
def map_signature(signature: str) -> tuple[str | None, str | None, str | None]:
    """
    Cauta primul tipar care se potriveste in numele semnaturii.
 
    Returneaza (cwe_id, eticheta, tiparul potrivit) sau (None, None, None).
    Tiparul potrivit se pastreaza pentru auditabilitate: peste trei luni
    vrei sa poti explica de ce o alerta a fost mapata la CWE-89.
    """
    low = signature.lower()
    for pattern, cwe, label in SIGNATURE_CWE_RULES:
        if pattern in low:
            return cwe, label, pattern
    return None, None, None
 
 
def map_alert(raw: dict) -> MappedAlert:
    signature = raw.get("signature", "")
    cwe, label, pattern = map_signature(signature)
    route, payload = split_url(raw.get("http_url"))
 
    return MappedAlert(
        alert_uuid=raw.get("alert_uuid", ""),
        timestamp=raw.get("timestamp", ""),
        signature=signature,
        severity=raw.get("severity", "unknown"),
        cwe_id=cwe,
        cwe_label=label,
        matched_pattern=pattern,
        src_ip=raw.get("src_ip"),
        route=route,
        payload=payload,
        http_method=raw.get("http_method"),
    )
 
 
def load_and_map(path: Path) -> list[MappedAlert]:
    with path.open() as fh:
        raw = json.load(fh)
    if isinstance(raw, dict):          # accepta si un raspuns _search brut
        raw = [h["_source"] for h in raw.get("hits", {}).get("hits", [])]
    return [map_alert(item) for item in raw]
 
 
def report(alerts: list[MappedAlert]) -> None:
    mapped = [a for a in alerts if a.triggers_code_scan]
    unmapped = [a for a in alerts if not a.triggers_code_scan]
 
    print(f"{len(alerts)} alerte")
    print(f"{len(mapped)} declanseaza scanare de cod")
    print(f"{len(unmapped)} nemapate (triaj normal, fara scanare)")
    print()
 
    for a in mapped:
        print(f"  {a.alert_uuid}  {a.cwe_id}  ({a.cwe_label})")
        print(f"      semnatura : {a.signature}")
        print(f"      potrivit  : '{a.matched_pattern}'")
        print(f"      ruta      : {a.route}")
        print(f"      payload   : {a.payload}")
        print()
 
    if unmapped:
        print("Nemapate:")
        for a in unmapped:
            print(f"  {a.alert_uuid}  {a.signature}")
        print()
 
    # Grupare pe CWE: astea sunt scanarile care trebuie rulate.
    # O scanare per (repo, CWE), nu per alerta -- vezi cache-ul din corelator.
    by_cwe: dict[str, int] = {}
    for a in mapped:
        by_cwe[a.cwe_id] = by_cwe.get(a.cwe_id, 0) + 1
    if by_cwe:
        print("Scanari necesare (una per CWE, indiferent cate alerte):")
        for cwe, count in sorted(by_cwe.items(), key=lambda kv: -kv[1]):
            print(f"  {cwe}  <- {count} alerte")
 
 
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path)
    p.add_argument("--out", type=Path, help="scrie alertele mapate ca JSON")
    args = p.parse_args()
 
    if not args.path.exists():
        print(f"Nu gasesc {args.path}", file=sys.stderr)
        return 1
 
    alerts = load_and_map(args.path)
    report(alerts)
 
    if args.out:
        args.out.write_text(
            json.dumps([asdict(a) for a in alerts], indent=2, ensure_ascii=False)
        )
        print(f"Scris: {args.out}")
 
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main())
