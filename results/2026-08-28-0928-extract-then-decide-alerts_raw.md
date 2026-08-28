# Benchmark extract-then-decide

## Conditii de rulare
- data: 2026-08-28T09:28:15
- git: ac48682+modificari-necomise
- alerte: ../groundtruth/alerts_raw.json (131 brute, 10 etichetate)
- ground truth: ../groundtruth/runs.csv
- distributie etichete: TP=4  FP=6
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
| FN (atac inchis) | 2 |
| TN (zgomot inchis) | 5 |
| FP (zgomot escaladat) | 1 |
| extragere esuata | 0 |

- TPR: 50.00%
- TNR: 83.33%
- FPR: 16.67%
- precizie: 66.67%
- rata de esec la extragere: 0.00%
- latenta medie: 4.59s (total 0.8 min)

### Statusuri de extragere
- ok: 10

### Verdicte
- benign_positive: 6
- actionable: 3
- fp_data: 1

## Tabele de contingenta pe trasatura

Rezultatul central al etapei 1: care intrebari separa efectiv clasele.
O trasatura a carei distributie e aceeasi pe TP si pe FP nu poarta
semnal si trebuie scoasa din schema.

### command_shape

| valoare | TP | FP |
|---|---|---|
| credential_access | 1 | 1 |
| log_manipulation | 1 | 0 |
| no_command_line | 0 | 1 |
| persistence_mechanism | 0 | 1 |
| routine_admin | 2 | 3 |

### parent_lineage

| valoare | TP | FP |
|---|---|---|
| interactive_shell | 1 | 0 |
| package_manager | 1 | 1 |
| scheduler_or_service | 1 | 1 |
| unknown_parent | 1 | 4 |

### naming_pattern

| valoare | TP | FP |
|---|---|---|
| conventional_system | 1 | 1 |
| generic_or_test_like | 0 | 2 |
| no_identifiers | 3 | 3 |

## Atacuri ratate

| regula Elastic | regula care a decis | verdict |
|---|---|---|
| Tampering of Shell Command-Line History | default | benign_positive |
| SUID/SGID Bit Set | default | benign_positive |

## Limitari

- n=10 dintr-un laborator cu un singur endpoint, 4 pozitive.
- o singura rulare per alerta; la temperature 0.0 extragerea e
  deterministica, dar asta nu spune nimic despre stabilitatea ei
  la reformulare -- pentru asta ruleaza cu --gate.
- pragul din R5 e o alegere, nu o masuratoare.
- rezultatul nu se extrapoleaza la productie.
