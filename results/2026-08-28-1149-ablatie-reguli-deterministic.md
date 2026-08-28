# Ablatie pe regulile arborelui de decizie

- data: 2026-08-28T11:49:48
- alerte: ../groundtruth/alerts_raw.json (115 etichetate, 5 TP / 110 FP)
- sursa trasaturilor: deterministic
- UNDETERMINED contabilizat ca: escalate

Metoda: extragere o singura data, apoi arborele reevaluat pe fiecare
submultime de reguli. Coloana FN se citeste prima -- o varianta care
taie mai mult zgomot dar rateaza mai multe atacuri nu e o imbunatatire.

| varianta | zgomot inchis | atacuri ratate | TNR | delta FN |
|---|---|---|---|---|
| toate regulile | 107/110 | 1/5 | 97.3% | +0 |
| fara R0-no-telemetry | 107/110 | 1/5 | 97.3% | +0 |
| fara R1-credential-access | 107/110 | 3/5 | 97.3% | +2 |
| fara R2-log-tampering | 108/110 | 2/5 | 98.2% | +1 |
| fara R3-manual-persistence | 109/110 | 2/5 | 99.1% | +1 |
| fara R4-risk-threshold | 107/110 | 1/5 | 97.3% | +0 |
| fara R5-automated-package-management | 107/110 | 1/5 | 97.3% | +0 |
| niciuna (doar implicitul) | 110/110 | 5/5 | 100.0% | +4 |

## Ce regula a decis, in varianta completa

| regula | alerte decise |
|---|---|
| default | 68 |
| R0-no-telemetry | 39 |
| R3-manual-persistence | 3 |
| R1-credential-access | 2 |
| R2-log-tampering | 2 |
| R5-automated-package-management | 1 |

Reguli care nu s-au aprins niciodata: R4-risk-threshold. Sunt cod mort pe setul asta -- fie conditia nu apare in date, fie o regula anterioara le fura mereu cazurile.

## Limitari

- 5 pozitive. O diferenta de un singur FN muta rata cu 20 de puncte, deci coloana FN e grosiera prin constructie.
- extractorul determinist a fost scris dupa ce alertele au fost
  vazute; e o margine superioara pentru stratul de trasaturi, nu o
  solutie propusa.
- ablatia masoara contributia unei reguli DATE fiind celelalte;
  nu e o descompunere aditiva.
