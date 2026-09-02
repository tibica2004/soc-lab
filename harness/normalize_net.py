"""
Normalizarea alertelor de retea (Suricata prin integrarea Elastic).

Integrarea Suricata mapeaza `eve.json` in ECS inainte de indexare, deci nu
lucram cu structura bruta a senzorului ci cu campuri standard: `url.path`,
`rule.name`, `source.ip`. Campurile brute raman disponibile sub
`suricata.eve.*` pentru ce nu e mapat.

Contractul e paralel cu `NormalizedAlert` din normalize.py, dar campurile
sunt altele: o alerta de retea nu are proces si linie de comanda, are ruta
si semnatura. Nu se forteaza intr-o structura comuna -- ar insemna campuri
goale peste tot si o falsa impresie de uniformitate.

`url.path` e piesa care conteaza: e puntea catre cod. O alerta de endpoint
nu are asa ceva, si de aceea corelarea cu codul e posibila doar pe ramura
web (vezi O-017 din registru).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NetworkAlert:
    """O alerta Suricata, normalizata."""

    doc_id: str
    timestamp: str

    # semnatura care s-a aprins
    signature: str
    signature_id: int
    category: str
    severity: int

    # ruta atacata -- puntea catre cod
    url_path: str | None
    url_query: str | None
    url_original: str | None
    http_method: str | None
    http_status: int | None

    # cine si catre cine
    source_ip: str | None
    source_port: int | None
    dest_ip: str | None
    dest_port: int | None

    # trasabilitate catre web_runs.csv
    user_agent: str | None

    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def request_id(self) -> str | None:
        """
        Identificatorul cererii din web_runs.csv, daca a fost trimis.

        Conventia: User-Agent de forma `soc-lab/w-001`. Inlocuieste
        ferestrele de timp folosite pe ramura de endpoint -- legatura
        alerta <-> rand de ground truth devine determinista.

        E o simplificare de laborator: in productie nu ai marcaj in cerere.
        De consemnat in raport.
        """
        ua = self.user_agent or ""
        if ua.startswith("soc-lab/"):
            return ua.split("/", 1)[1].strip()
        return None

    @property
    def has_route(self) -> bool:
        """Daca alerta poate declansa corelarea cu codul."""
        return bool(self.url_path)


def _dig(source: dict[str, Any], *path: str) -> Any:
    """Coboara prin chei imbricate, None daca lipseste ceva pe drum."""
    node: Any = source
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def normalize_network_alert(hit: dict[str, Any]) -> NetworkAlert:
    """Un `hit` din raspunsul Elasticsearch -> NetworkAlert."""
    source = hit.get("_source", hit)
    eve = _dig(source, "suricata", "eve") or {}
    alert = eve.get("alert") or {}

    return NetworkAlert(
        doc_id=hit.get("_id", ""),
        timestamp=source.get("@timestamp", ""),
        signature=_dig(source, "rule", "name") or alert.get("signature") or "",
        signature_id=int(
            _dig(source, "rule", "id") or alert.get("signature_id") or 0
        ),
        category=_dig(source, "rule", "category") or alert.get("category") or "",
        severity=int(alert.get("severity") or 0),
        url_path=_dig(source, "url", "path"),
        url_query=_dig(source, "url", "query"),
        url_original=_dig(source, "url", "original"),
        http_method=_dig(source, "http", "request", "method"),
        http_status=_dig(source, "http", "response", "status_code"),
        source_ip=_dig(source, "source", "ip"),
        source_port=_dig(source, "source", "port"),
        dest_ip=_dig(source, "destination", "ip"),
        dest_port=_dig(source, "destination", "port"),
        user_agent=_dig(source, "user_agent", "original"),
        raw=source,
    )


def load_network_alerts(path: Path) -> list[NetworkAlert]:
    """Citeste un export Elasticsearch salvat pe disc."""
    payload = json.loads(path.read_text())
    hits = payload.get("hits", {}).get("hits", payload)
    return [normalize_network_alert(h) for h in hits]


# ---------------------------------------------------------------------------
# Dedup pentru alerte de retea
# ---------------------------------------------------------------------------

def network_fingerprint(alert: NetworkAlert) -> str:
    """
    Amprenta pentru deduplicare.

    `fingerprint` din normalize.py foloseste proces si linie de comanda --
    concepte care nu exista aici. Pe retea, echivalentul e semnatura plus
    sursa plus ruta: acelasi scaner care loveste aceeasi ruta repetat
    produce aceeasi amprenta.

    NU include portul sursa, care difera la fiecare conexiune, si nici
    query string-ul, ca sa nu scape un scaner care variaza un parametru.
    """
    return "|".join([
        str(alert.signature_id),
        alert.source_ip or "-",
        alert.url_path or "-",
    ])


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("utilizare: python3 normalize_net.py <export.json>")
        raise SystemExit(1)

    alerts = load_network_alerts(Path(sys.argv[1]))
    print(f"{len(alerts)} alerte de retea")

    from collections import Counter

    print("\nPe semnatura:")
    for sig, n in Counter(a.signature for a in alerts).most_common(10):
        print(f"  {n:4}  {sig}")

    with_route = sum(1 for a in alerts if a.has_route)
    print(f"\nCu ruta (corelabile cu codul): {with_route}/{len(alerts)}")

    with_rid = sum(1 for a in alerts if a.request_id)
    print(f"Cu request_id in User-Agent:   {with_rid}/{len(alerts)}")

    fps = {network_fingerprint(a) for a in alerts}
    print(f"\nAmprente unice: {len(fps)} din {len(alerts)} "
          f"(dedup ar taia {len(alerts) - len(fps)})")
