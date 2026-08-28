# Ablatie pe regulile arborelui de decizie

- data: 2026-08-28T11:48:30
- alerte: ../groundtruth/alerts_raw.json (115 etichetate, 5 TP / 110 FP)
- sursa trasaturilor: model
- UNDETERMINED contabilizat ca: escalate

Metoda: extragere o singura data, apoi arborele reevaluat pe fiecare
submultime de reguli. Coloana FN se citeste prima -- o varianta care
taie mai mult zgomot dar rateaza mai multe atacuri nu e o imbunatatire.

| varianta | zgomot inchis | atacuri ratate | TNR | delta FN |
|---|---|---|---|---|
| toate regulile | 106/110 | 3/5 | 96.4% | +0 |
| fara R0-no-telemetry | 106/110 | 3/5 | 96.4% | +0 |
| fara R1-credential-access | 109/110 | 4/5 | 99.1% | +1 |
| fara R2-log-tampering | 107/110 | 4/5 | 97.3% | +1 |
| fara R3-manual-persistence | 106/110 | 3/5 | 96.4% | +0 |
| fara R4-risk-threshold | 106/110 | 3/5 | 96.4% | +0 |
| fara R5-automated-package-management | 106/110 | 3/5 | 96.4% | +0 |
| niciuna (doar implicitul) | 110/110 | 5/5 | 100.0% | +2 |

## Ce regula a decis, in varianta completa

| regula | alerte decise |
|---|---|
| default | 87 |
| R0-no-telemetry | 22 |
| R1-credential-access | 4 |
| R2-log-tampering | 2 |

Reguli care nu s-au aprins niciodata: R3-manual-persistence, R4-risk-threshold, R5-automated-package-management. Sunt cod mort pe setul asta -- fie conditia nu apare in date, fie o regula anterioara le fura mereu cazurile.

## Limitari

- 5 pozitive. O diferenta de un singur FN muta rata cu 20 de puncte, deci coloana FN e grosiera prin constructie.
- ablatia masoara contributia unei reguli DATE fiind celelalte;
  nu e o descompunere aditiva.
