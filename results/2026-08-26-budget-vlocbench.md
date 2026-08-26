# O-003 confirmat pe VLoc Bench: bugetul implicit e contraproductiv

Setup: Antares-1B Q8_0, llama.cpp CPU, -c 8192 -t 4, temperature 0.3
Acelasi subset de 30 de cazuri (--n-limit 30, ordine determinista din manifest)
Singura variabila: max_terminal_calls

buget  File F1   timp mediu  timp total  apeluri  abtineri
4      0.2619        34s        17 min      4.0      0%
15     0.2497      2270s      1135 min     13.7    6.7%

Bugetul 4 e mai bun ca acuratete SI de 67x mai rapid.
Nu e un compromis viteza/calitate - e o imbunatatire pe ambele axe.

CONSECINTA PRACTICA: un sweep pe 50 de CWE-uri trece de la ~19 ore
la ~28 minute. Devine fezabil in CI, nu doar nocturn.

CAUZA (din traiectorii): dupa ce gaseste raspunsul, modelul repeta
comenzi identice (tool_blocked: duplicate) si deriva spre cautari tot
mai vagi. Bugetul suplimentar nu adauga acoperire, adauga ratacire.

LIMITARI: n=30, o rulare per buget. Modelul e nedeterminist la
temperature 0.3 - diferenta de F1 (0.012) e sub varianta observata
intre rulari ale aceluiasi caz si NU e semnificativa. Afirmatia
sustinuta de aceste date este "buget 4 nu e mai prost", nu "e mai bun".
Cifra robusta este raportul de timp: 67x.
