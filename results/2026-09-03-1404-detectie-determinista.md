# Detectie determinista pe evenimente HTTP

- data: 2026-09-03T14:04:59
- evenimente: 28, dintre care 28 etichetate

Interogheaza `event_type: http`, nu `alert`. Detectia se face in cod.

| varianta | atacuri prinse | ratate | fals pozitive |
|---|---|---|---|
| toate regulile | 7/12 | 5 | 0/16 |
| fara R1-path-traversal | 5/12 | 7 | 0/16 |
| fara R2-command-injection | 6/12 | 6 | 0/16 |
| fara R3-sqli-tautology | 6/12 | 6 | 0/16 |
| fara R4-ssrf-internal | 7/12 | 5 | 0/16 |
| fara R5-xss | 7/12 | 5 | 0/16 |
| fara R6-secrets-probe | 5/12 | 7 | 0/16 |
| niciuna | 0/12 | 12 | 0/16 |

## Comparatie cu ET Open

M1 pe acelasi trafic: 1 din 6. Determinist: 7 din 12.

## Ce regula a prins ce

- R1-path-traversal: 3
- R6-secrets-probe: 2
- R2-command-injection: 1
- R3-sqli-tautology: 1

Reguli care nu s-au aprins: R4-ssrf-internal, R5-xss.

## Atacuri ratate

- w-002 (privilege_escalation_role_grant)
- w-003 (ssrf_image_url)
- w-004 (missing_authorization)
- w-005 (idor_other_user)
- w-006 (info_disclosure_response_header)

## Limitari

- Regulile scrise DUPA ce s-au vazut payload-urile: optimist
  partinitoare, ca extract_det.py.
- Doar ruta si query string. Payload-urile din corpul cererii
  (w-002, w-003, w-005) nu sunt vizibile: Suricata nu logheaza corpul.
  Limitare de telemetrie, nu de reguli.
- Detectia prin tipare prinde ce seamana cu ce stii deja.
