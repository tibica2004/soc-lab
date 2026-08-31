> **RETRAS 2026-08-28.** Cele 10 TP includeau alerte din ferestrele
> `T1059.004` (12:12:09) si `T1543.002` (12:17:32), tehnici care nu au produs
> detectii proprii. Alertele din ferestrele lor apartineau tehnicilor
> precedente (shadow file 12:10:36, cron 12:10:44, SUID 12:15:00) sau erau
> zgomot de discovery — 32 de "System Owner/User Discovery Linux" intr-o
> singura fereastra. Cele doua randuri au fost scoase din `runs.csv`.
>
> Cu etichetare curata: **115 alerte, 5 TP / 110 FP, `prefilter_safe` taie
> 59% din zgomot, FN 0/5.** Vezi `2026-08-28-prefilter-baseline.md`.
>
> Afectat si O-001: cu etichetare curata, `dedup` are FN 0%, nu 20%. Motivul
> empiric pentru introducerea lui `dedup_safe` nu se mai sustine, desi
> prudenta ramane justificata pe alte temeiuri (O-002).

---

# Baseline determinist al pre-filtrului (n=115, 10 TP / 105 FP)

triager           auto-close  zgomot taiat  FN rate
none                      0%           0%     0.0%
building_block           55%          60%     0.0%
dedup                    49%          52%    10.0%
dedup_safe               46%          50%     0.0%
prefilter                59%          64%    10.0%
prefilter_safe           57%          62%     0.0%   <- BASELINE
all                     100%         100%   100.0%

BASELINE: prefilter_safe = building_block + dedup prudent.
62% din zgomot eliminat, zero atacuri ratate. Zero LLM.

Orice contributie a modelului se masoara PESTE aceasta cifra.

DOUA CORECTURI CARE AU PRODUS-O:
1. fingerprint include process.command_line
   Fara el, un `useradd` de deploy si unul de atac sunt identice.
   FN rate 20% -> 10%.
2. dedup refuza sa inchida cand command_line lipseste (27% din alerte, O-002)
   FN rate 10% -> 0%. Cost: 2 puncte de reducere de zgomot.

PRINCIPIU CONFIRMAT EMPIRIC: combinarea filtrelor e aditiva doar daca
fiecare componenta are FN 0. prefilter (64%, FN 10%) parea mai bun decat
prefilter_safe (62%, FN 0%) - cele 2 puncte in plus costau un atac din zece.

LIMITARI: n=115, un singur endpoint, 10 TP. Pragul de <2% FN nu poate fi
verificat semnificativ cu 10 pozitive - un singur TP ratat inseamna 10%.
Necesita validare pe date de productie.
