# Benchmark extract-then-decide

## Conditii de rulare
- data: 2026-08-28T09:09:36
- git: ac48682+modificari-necomise
- alerte: ../groundtruth/alerts_raw.json (131 brute, 10 etichetate)
- ground truth: ../groundtruth/runs.csv
- distributie etichete: TP=4  FP=6
- model: /home/tiberiu/antares-1b-q8_0.gguf
- cuantizare: Q8_0
- temperature: 0.0   n_ctx: 2048
- formulare: a
- reguli active: R0-no-telemetry, R1-reverse-shell, R2-credential-access, R3-log-tampering, R4-manual-persistence, R5-risk-threshold, R6-automated-package-management, R7-read-only-no-target
- UNDETERMINED contabilizat ca: escalate

## Rezultate

| categorie | n |
|---|---|
| TP (atac escaladat) | 2 |
| FN (atac inchis) | 2 |
| TN (zgomot inchis) | 1 |
| FP (zgomot escaladat) | 5 |
| extragere esuata | 0 |

- TPR: 50.00%
- TNR: 16.67%
- FPR: 83.33%
- precizie: 28.57%
- rata de esec la extragere: 0.00%
- latenta medie: 5.85s (total 1.0 min)

### Statusuri de extragere
- ok: 10

### Verdicte
- actionable: 7
- benign_positive: 2
- fp_logic: 1

## Tabele de contingenta pe trasatura

Rezultatul central al etapei 1: care intrebari separa efectiv clasele.
O trasatura a carei distributie e aceeasi pe TP si pe FP nu poarta
semnal si trebuie scoasa din schema.

### command_shape

| valoare | TP | FP |
|---|---|---|
| credential_access | 1 | 0 |
| reverse_shell | 2 | 5 |
| routine_admin | 1 | 1 |

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
| conventional_system | 1 | 2 |
| generic_or_test_like | 0 | 3 |
| no_identifiers | 3 | 1 |

### target_sensitivity

| valoare | TP | FP |
|---|---|---|
| no_specific_target | 1 | 0 |
| scheduling_or_service_config | 3 | 6 |

### action_reversibility

| valoare | TP | FP |
|---|---|---|
| modifies_system_state | 0 | 2 |
| no_evidence | 1 | 0 |
| reads_only | 3 | 4 |

## Atacuri ratate

| regula Elastic | regula care a decis | verdict |
|---|---|---|
| Potential Shadow File Read via Command Line Utilities | default | benign_positive |
| SUID/SGID Bit Set | R7-read-only-no-target | fp_logic |

## Limitari

- n=10 dintr-un laborator cu un singur endpoint, 4 pozitive.
- o singura rulare per alerta; la temperature 0.0 extragerea e
  deterministica, dar asta nu spune nimic despre stabilitatea ei
  la reformulare -- pentru asta ruleaza cu --gate.
- pragul din R5 e o alegere, nu o masuratoare.
- rezultatul nu se extrapoleaza la productie.
