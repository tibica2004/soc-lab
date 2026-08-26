# Ablatie pre-filtru, cu etichetare corectata (n=115, 10 TP / 105 FP)

Corectura de metoda: TP cere potrivire pe fereastra SI pe regula asteptata.
Anterior, doar fereastra -> 7 tehnici produceau 65 "TP" (alertele de
discovery de la activitatea normala cadeau in fereastra testelor).

triager          auto-close  zgomot taiat  FN rate
none                     0%           0%      0.0%
building_block          55%          60%      0.0%   <- singurul valid
dedup                   52%          55%     20.0%
prefilter               60%          64%     20.0%
all                    100%         100%    100.0%

CONSTATARE PRINCIPALA: excluderea alertelor building_block taie 60% din
zgomot fara nicio pierdere de TP. E o verificare de camp, nu o euristica.

IPOTEZA INFIRMATA: dedup-ul pe fingerprint (rule_id, host, user, process)
parea cel mai puternic filtru (65% reducere pe setul brut, O-001). Cu
etichetare corecta, rateaza 2 din 10 atacuri.
Cauza: zgomotul benign si atacul produc acelasi fingerprint. Un `useradd`
de la scriptul de deploy si unul de la Atomic Red Team sunt identice pe
cele patru campuri. Primul escaladeaza, al doilea se inchide ca duplicat.

CONSECINTA: `prefilter` (building_block + dedup) e MAI PROST decat
building_block singur. Combinarea filtrelor nu e aditiva.
Dedup-ul are nevoie de un camp discriminant in plus (linie de comanda,
proces parinte) - exact contextul care lipseste la 27% din alerte (O-002).

LIMITARI: n=115 dintr-un laborator cu un singur endpoint, 10 TP.
Nu se extrapoleaza la productie.
