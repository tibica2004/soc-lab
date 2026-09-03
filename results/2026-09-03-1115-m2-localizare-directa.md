# M2 — localizarea vulnerabilitatii (direct, fara detectie)

- data: 2026-09-03T11:15:16
- repo: ../sample_repo
- cazuri testabile: 6 (cu CWE si fisier asteptat)

Corelatorul e hranit direct din web_runs.csv, ocolind Suricata.
Masoara strict: dat fiind CWE-ul corect, localizeaza Antares fisierul
vulnerabil? Detectia are masuratoare separata (M1).

| cerere | CWE | fisier asteptat | localizat | fisiere | overlap |
|---|---|---|---|---|---|
| w-001 | CWE-78 | `utils.py` | DA | 1 | 0.50 |
| w-002 | CWE-269 | `update_user_role_service.py` | nu | 8 | 0.00 |
| w-003 | CWE-918 | `utils.py` | nu | 1 | 0.00 |
| w-004 | CWE-862 | `delete_menu_item_service.py` | nu | 4 | 0.00 |
| w-005 | CWE-639 | `update_profile_service.py` | nu | 4 | 0.00 |
| w-006 | CWE-200 | `service.py` | nu | 5 | 0.00 |

**1/6 localizate corect.**

## Fata de predictia consemnata

Predictia din web_runs.csv, scrisa inainte de rulare:
reusita pe CWE-78 si CWE-269, partiala pe CWE-918, esec pe
CWE-862, CWE-639, CWE-200 (defectul e absenta unei verificari, O-004).

## Limitari

- File F1 0.305 pe benchmark: rezultatul de aici e pe un singur repo
  mic, cu un caz per CWE. Confirma sau infirma predictia, nu produce
  o cifra generalizabila.
- 'localizat' inseamna ca fisierul corect e in lista returnata, nu ca
  e singurul. Numarul de fisiere spune cat de precisa e localizarea.
- Modelul nu da verdict; intoarce fisiere. Absenta suprafetei reale
  (N2) nu se testeaza aici -- vezi web_correlate.py.
