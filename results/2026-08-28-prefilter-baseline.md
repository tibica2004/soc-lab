# Baseline determinist al pre-filtrului — etichetare curata

Setup: `ablation.py --alerts groundtruth/alerts_raw.json --truth groundtruth/runs.csv --ablation`
Data: 2026-08-28
Set: 131 alerte brute, 115 etichetate (16 in afara oricarei ferestre), **5 TP / 110 FP**
Ground truth: `runs.csv`, potrivire pe fereastra SI pe regula asteptata

| triager | auto-close | zgomot taiat | FN rate |
|---|---|---|---|
| none | 0% | 0% | 0/5 |
| building_block | 55% | 57% | 0/5 |
| dedup | 49% | 51% | 0/5 |
| dedup_safe | 46% | 48% | 0/5 |
| prefilter | 59% | 62% | 0/5 |
| **prefilter_safe** | **57%** | **59%** | **0/5** |
| all | 100% | 100% | 5/5 |

**BASELINE: `prefilter_safe` — 59% din zgomot eliminat, 0 din 5 atacuri
ratate, zero LLM.** Orice contributie a modelului se masoara peste aceasta
cifra.

## Ce s-a corectat fata de 2026-08-26

Raportul anterior consemna 10 TP / 105 FP si `prefilter_safe` la 62%. Cele
cinci TP in plus veneau din ferestrele a doua tehnici care nu au produs
detectii proprii:

- `T1059.004` (12:12:09, bash script + ping) — alertele din fereastra ei
  apartineau tehnicilor de la 12:10:36 si 12:10:44. Ferestrele de trei minute
  se suprapun.
- `T1543.002` (12:17:32, systemd service) — 41 de alerte in fereastra, dintre
  care 32 de tip discovery, plus trei care apartineau tehnicii SUID de la
  12:15:00. Randul era marcat "de confirmat" in CSV.

Ambele randuri au fost scoase. Un rand etichetat TP care nu poate produce
niciodata un TP nu adauga informatie; creeaza doar impresia unui numitor mai
mare. Rularea de dupa stergere e identica cu cea de dinainte, ceea ce
confirma ca randurile nu contribuiau. Cifra reala a fost tot timpul 5.

## Efect asupra O-001

Cu etichetare curata, `dedup` are FN 0%, nu 20%. Cele doua "atacuri ratate de
dedup" din raportul anterior erau alerte din ferestre contaminate.

Afirmatia "deduplicarea pe fingerprint rateaza 2 din 10 atacuri" **nu mai are
sustinere in date** si nu se citeaza. Ce ramane valid:

- fingerprint-ul care include `process.command_line` e mai discriminant decat
  cel pe patru campuri — argument de proiectare, nu masuratoare;
- refuzul de a inchide cand linia de comanda lipseste ramane justificat prin
  O-002, nu prin FN observat;
- pe setul asta, `dedup` si `dedup_safe` au acelasi FN. Diferenta dintre ele e
  de 3 puncte de zgomot taiat, in favoarea variantei mai putin prudente.

## Limitari

- **5 pozitive.** Cu zero esecuri din cinci, limita superioara a intervalului
  de incredere 95% pentru rata reala de FN e in jur de 45%. Afirmatia
  sustinuta este "nu s-au observat FN pe 5 pozitive", nu "nu rateaza atacuri".
- Pragul declarat de <2% FN nu poate fi verificat semnificativ cu 5 pozitive.
  Un singur TP ratat inseamna 20%.
- 110 negative dintr-un singur script de zgomot (`apt-get`), pe un singur
  endpoint. Diversitatea e mica, deci reducerea de 59% e optimista fata de un
  mediu real.
- Nu se extrapoleaza la productie.
- Ferestrele T1059.004 si T1543.002 nu au produs detectii proprii, dar
  contribuie cu 43 de alerte la numitorul de zgomot. Sunt pastrate ca FP
  pentru ca sunt zgomot real pe care pre-filtrul trebuie sa-l trateze, si
  pentru ca un numitor mai mare e mai conservator. Scoase din set, aceleasi
  triagere taie 40% in loc de 59%. Cifra principala depinde deci si de o
  alegere de definitie, nu doar de masuratoare.
