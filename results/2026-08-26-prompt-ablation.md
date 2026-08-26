# Ablatie de prompt pe abtinere (faza B, n=30, buget 4)

prompt     TNR      cazuri  descriere
oficial    0.0000    0/30   formulare neutra
v1         0.0667    2/30   "may or may not", cost asimetric explicit
v2         0.0667    2/30   "about half do NOT contain this"
v3         0.0333    1/30   indiciu ca repo-ul poate fi deja patch-uit
v4         0.0333    1/30   v1 + v3 combinate

SUSTINUT: abtinerea nu e o incapacitate arhitecturala. Orice reformulare
duce TNR de la 0 absolut la nenul.

NU E SUSTINUT: ca vreo varianta e mai buna decat alta. Diferenta 1 vs 2
cazuri din 30 e zgomot.

CONCLUZIE: comportamentul de abtinere e aproape insensibil la prompt.
Explicatie probabila: GRPO a intarit submiterea ca politica; instructiunile
din prompt nu suprascriu o politica invatata prin RL.

CONSECINTA: problema se rezolva prin filtrare externa in harness (O-005)
sau prin fine-tuning cu traiectorii care includ abtineri corecte.
NU prin prompt engineering.
