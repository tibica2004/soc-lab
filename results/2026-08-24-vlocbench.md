# VLoc Bench, faza A — Antares-1B Q8_0 pe llama.cpp CPU

n=95 valide din 100 (5 excluse: 0-1 apeluri terminal = timeout de infra)
Setup: max_terminal_calls 15, temperature 0.3, context 8192

File F1 mediu:  0.305
  F1 = 0.00:  42 cazuri (44%)
  F1 = 1.00:   9 cazuri (9%)
  abtineri:    1 caz

REFERINTA (Cisco, technical report):
  Antares-1B GRPO   0.209
  GPT-5.5 (xhigh)   0.229  (cel mai bun din benchmark)

Rezultatul e PESTE cifra publicata. Explicatii posibile de verificat:
subset diferit de cazuri (95 din 500), varianta de esantionare,
diferente de harness sau de cuantizare.

VARIANTA MARE INTRE RULARI ale aceluiasi caz:
  1iGUUYCE: 0.00 / 1.00 / 0.40
  1ANd82uK: 0.67 / 0.00 / 0.00
  0IdCIbCr: 0.33 / 0.22 / 0.33
La temperature 0.3 o singura rulare nu caracterizeaza un caz.

MODELUL NU SE ABTINE: 1 abtinere din 95. Submite fisiere chiar cand
greseste complet (42 de cazuri cu F1=0). Nu are calibrare interna de
incredere -> semnalele externe (numar de fisiere, vezi O-005) sunt
singura sursa de incertitudine disponibila harness-ului.

