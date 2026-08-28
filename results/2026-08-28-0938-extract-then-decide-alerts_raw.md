# Benchmark extract-then-decide

## Conditii de rulare
- data: 2026-08-28T09:38:56
- git: ac48682+modificari-necomise
- alerte: ../groundtruth/alerts_raw.json (131 brute, 115 etichetate)
- ground truth: ../groundtruth/runs.csv
- distributie etichete: TP=5  FP=110
- model: /home/tiberiu/antares-1b-q8_0.gguf
- cuantizare: Q8_0
- temperature: 0.0   n_ctx: 2048
- formulare: a
- reguli active: R0-no-telemetry, R1-credential-access, R2-log-tampering, R3-manual-persistence, R4-risk-threshold, R5-automated-package-management
- UNDETERMINED contabilizat ca: escalate

## Rezultate

| categorie | n |
|---|---|
| TP (atac escaladat) | 2 |
| FN (atac inchis) | 3 |
| TN (zgomot inchis) | 106 |
| FP (zgomot escaladat) | 4 |
| extragere esuata | 0 |

- TPR: 40.00%
- TNR: 96.36%
- FPR: 3.64%
- precizie: 33.33%
- rata de esec la extragere: 0.00%
- latenta medie: 4.33s (total 8.3 min)

### Statusuri de extragere
- ok: 115

### Verdicte
- benign_positive: 87
- fp_data: 22
- actionable: 6

## Tabele de contingenta pe trasatura

Rezultatul central al etapei 1: care intrebari separa efectiv clasele.
O trasatura a carei distributie e aceeasi pe TP si pe FP nu poarta
semnal si trebuie scoasa din schema.

### command_shape

| valoare | TP | FP |
|---|---|---|
| credential_access | 1 | 3 |
| log_manipulation | 1 | 1 |
| no_command_line | 0 | 22 |
| persistence_mechanism | 1 | 30 |
| routine_admin | 2 | 54 |

### parent_lineage

| valoare | TP | FP |
|---|---|---|
| interactive_shell | 1 | 0 |
| package_manager | 1 | 41 |
| scheduler_or_service | 1 | 5 |
| unknown_parent | 2 | 64 |

### naming_pattern

| valoare | TP | FP |
|---|---|---|
| conventional_system | 1 | 24 |
| generic_or_test_like | 1 | 69 |
| no_identifiers | 3 | 17 |

## Atacuri ratate

| regula Elastic | regula care a decis | verdict |
|---|---|---|
| Tampering of Shell Command-Line History | default | benign_positive |
| SUID/SGID Bit Set | default | benign_positive |
| Linux User Account Creation | default | benign_positive |

## Limitari

- n=115 dintr-un laborator cu un singur endpoint, 5 pozitive.
- o singura rulare per alerta; la temperature 0.0 extragerea e
  deterministica, dar asta nu spune nimic despre stabilitatea ei
  la reformulare -- pentru asta ruleaza cu --gate.
- pragul din R5 e o alegere, nu o masuratoare.
- rezultatul nu se extrapoleaza la productie.
