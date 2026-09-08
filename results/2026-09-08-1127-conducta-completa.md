# Conducta completa: trafic -> detectie -> cod -> verdict

- data: 2026-09-08T11:27:50
- evenimente HTTP: 33
- semnalate de detectia determinista: 8
- repo: ../sample_repo

Detectia vine din regulile proprii pe trafic HTTP brut, nu din
semnaturile ET Open (M1: 1/6). Verdictul se ia in cod, nu in model.

## Prioritati

- low: 7
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

## Limitari

- Regulile de detectie sunt scrise dupa ce s-au vazut payload-urile.
  Optimist partinitoare, ca extract_det.py.
- Payload-urile din corpul cererii nu sunt vizibile: Suricata nu
  logheaza corpul. Trei atacuri din sase raman inaccesibile.
- Antares localizeaza 1 din 6 CWE-uri pe acest repo (M2).
  Un caz traverseaza lantul doar daca ambele straturi il prind.
- Prag de suprapunere 0.30, ales nu masurat.
