# Benchmark extract-then-decide

## Conditii de rulare
- data: 2026-08-28T09:47:59
- git: ac48682+modificari-necomise
- alerte: ../groundtruth/alerts_raw.json (131 brute, 115 etichetate)
- ground truth: ../groundtruth/runs.csv
- distributie etichete: TP=5  FP=110
- sursa trasaturilor: deterministic
- model: (determinist -- fara model)
- cuantizare: n/a
- temperature: 0.0   n_ctx: 0
- formulare: a
- reguli active: R0-no-telemetry, R1-credential-access, R2-log-tampering, R3-manual-persistence, R4-risk-threshold, R5-automated-package-management
- UNDETERMINED contabilizat ca: escalate

## Rezultate

| categorie | n |
|---|---|
| TP (atac escaladat) | 4 |
| FN (atac inchis) | 1 |
| TN (zgomot inchis) | 107 |
| FP (zgomot escaladat) | 3 |
| extragere esuata | 0 |

- TPR: 80.00%
- TNR: 97.27%
- FPR: 2.73%
- precizie: 57.14%
- rata de esec la extragere: 0.00%
- latenta medie: 0.00s (total 0.0 min)

### Statusuri de extragere
- ok: 115

### Verdicte
- benign_positive: 69
- fp_data: 39
- actionable: 7

## Tabele de contingenta pe trasatura

Rezultatul central al etapei 1: care intrebari separa efectiv clasele.
O trasatura a carei distributie e aceeasi pe TP si pe FP nu poarta
semnal si trebuie scoasa din schema.

### command_shape

| valoare | TP | FP |
|---|---|---|
| credential_access | 2 | 0 |
| log_manipulation | 1 | 1 |
| no_command_line | 1 | 38 |
| package_management | 0 | 2 |
| persistence_mechanism | 1 | 2 |
| routine_admin | 0 | 67 |

### parent_lineage

| valoare | TP | FP |
|---|---|---|
| interactive_shell | 4 | 62 |
| scheduler_or_service | 0 | 1 |
| unknown_parent | 1 | 47 |

### naming_pattern

| valoare | TP | FP |
|---|---|---|
| conventional_system | 3 | 56 |
| generic_or_test_like | 1 | 5 |
| no_identifiers | 1 | 49 |

## Atacuri ratate

| regula Elastic | regula care a decis | verdict |
|---|---|---|
| Linux User Account Creation | R0-no-telemetry | fp_data |

## Limitari

- n=115 dintr-un laborator cu un singur endpoint, 5 pozitive.
- o singura rulare per alerta; la temperature 0.0 extragerea e
  deterministica, dar asta nu spune nimic despre stabilitatea ei
  la reformulare -- pentru asta ruleaza cu --gate.
- pragul din R5 e o alegere, nu o masuratoare.
- rezultatul nu se extrapoleaza la productie.
