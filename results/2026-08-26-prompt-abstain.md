# Efectul promptului asupra abtinerii

Acelasi model, acelasi buget (4), acelasi subset (n=30).
Singura variabila: formularea promptului de utilizator.

                  oficial   abstain
Faza A  File F1    0.2619    0.2830
Faza B  TNR        0.0000    0.0667
Faza B  FPR        1.0000    0.9333

Modificari fata de promptul oficial:
- "may or may not contain this vulnerability. Many codebases do not"
  (elimina presupozitia ca vulnerabilitatea exista)
- "concrete evidence in the code itself, not merely files that handle
  related functionality" (ataca tiparul de esec observat in O-004)
- cost asimetric explicit: un fals pozitiv trimite un analist sa
  verifice cod curat

CONCLUZIE SUSTINUTA: abtinerea nu e o incapacitate a modelului, e o
comportare nesolicitata de prompt. TNR a trecut de la 0 absolut la
nenul fara pierdere de F1.

NU E SUSTINUT: cat de mult ajuta. 2 cazuri din 30. Diferenta de F1
(+0.021) e sub varianta observata intre rulari ale aceluiasi caz.

DIRECTIE: daca 5 minute de prompt muta TNR de la 0 la 0.067, merita
testat un prompt iterat sistematic si, eventual, fine-tuning pe
traiectorii care includ abtineri corecte.
