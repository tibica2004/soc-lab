# Conducta completa: trafic -> detectie -> cod -> verdict

- data: 2026-09-08T11:23:33
- evenimente HTTP: 28
- semnalate de detectia determinista: 7
- repo: ../sample_repo

Detectia vine din regulile proprii pe trafic HTTP brut, nu din
semnaturile ET Open (M1: 1/6). Verdictul se ia in cod, nu in model.

## Prioritati

- high: 6
- urgent: 1

## Cazuri care traverseaza tot lantul

Detectat de stratul propriu, mapat la CWE, localizat de Antares,
si confirmat prin potrivirea rutei cu calea fisierului.

| cerere | regula | CWE | fisier | overlap |
|---|---|---|---|---|
| w-001 | R2-command-injection | CWE-78 | `app/apis/admin/utils.py` | 1.00 |

## Toate escaladarile

**w-001** (P) — `/admin/stats/disk` — R2-command-injection — urgent
- fisier: `app/apis/admin/utils.py` (overlap 1.00)
- finding cunoscut din audit: app/apis/admin/utils.py [antares, semgrep] -- modelul nu a fost chemat
- suprafata confirmata: 1 fisiere pentru CWE-78
- ruta atacata se potriveste cu app/apis/admin/utils.py (suprapunere 1.00)
- tentativa tintita pe cod vulnerabil identificat

**w-011** (N2) — `/orders` — R1-path-traversal — high
- suprafata confirmata: 1 fisiere pentru CWE-22
- localizare precisa, dar ruta nu se potriveste cu fisierele

**w-012** (N2) — `/token` — R3-sqli-tautology — high
- suprafata confirmata: 1 fisiere pentru CWE-89
- localizare precisa, dar ruta nu se potriveste cu fisierele

**w-013** (N2) — `/orders/1` — R1-path-traversal — high
- suprafata confirmata: 1 fisiere pentru CWE-22
- localizare precisa, dar ruta nu se potriveste cu fisierele

**w-020** (N3) — `/wp-admin/setup-config.php` — R6-secrets-probe — high
- suprafata confirmata: 1 fisiere pentru CWE-200
- localizare precisa, dar ruta nu se potriveste cu fisierele

**w-021** (N3) — `/.env` — R6-secrets-probe — high
- suprafata confirmata: 1 fisiere pentru CWE-200
- localizare precisa, dar ruta nu se potriveste cu fisierele

**w-022** (N3) — `/etc/passwd` — R1-path-traversal — high
- suprafata confirmata: 1 fisiere pentru CWE-22
- localizare precisa, dar ruta nu se potriveste cu fisierele

## Limitari

- Regulile de detectie sunt scrise dupa ce s-au vazut payload-urile.
  Optimist partinitoare, ca extract_det.py.
- Payload-urile din corpul cererii nu sunt vizibile: Suricata nu
  logheaza corpul. Trei atacuri din sase raman inaccesibile.
- Antares localizeaza 1 din 6 CWE-uri pe acest repo (M2).
  Un caz traverseaza lantul doar daca ambele straturi il prind.
- Prag de suprapunere 0.30, ales nu masurat.
