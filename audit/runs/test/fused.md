# Coada de triaj — 2026-09-08T07:09:46Z

- Repo: `/home/tiberiu/soc-lab/sample_repo`
- Surse: semgrep, antares
- Fisiere candidate: 6  (din 7 findings)
- Intrari in baseline: 0

Ordinea e dupa acordul dintre unelte. Incepe de sus.


## ambele unelte, acelasi CWE

- **`app/apis/admin/utils.py`** (linii 1, 9) — CWE-78  _[antares, semgrep]_
    - semgrep: Found 'subprocess' function 'run' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates curre
    - antares: CWE-78: fisier candidat, localizat de Antares (1 fisiere returnate pentru acest CWE).

## doar Semgrep (cu linie)

- **`app/apis/auth/utils/jwt_auth.py`** (linii 32) — CWE-287  _[semgrep]_
    - semgrep: Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actor
- **`app/apis/orders/services/get_order_status.py`** (linii 41) — CWE-89  _[semgrep]_
    - semgrep: sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and t

## doar Antares (doar fisier)

- **`app/apis/menu/utils.py`** (linii 1) — CWE-918  _[antares]_
    - antares: CWE-918: fisier candidat, localizat de Antares (2 fisiere returnate pentru acest CWE).
- **`app/apis/orders/utils.py`** (linii 1) — CWE-918  _[antares]_
    - antares: CWE-918: fisier candidat, localizat de Antares (2 fisiere returnate pentru acest CWE).
- **`app/apis/users/services/update_user_role_service.py`** (linii 1) — CWE-269  _[antares]_
    - antares: CWE-269: fisier candidat, localizat de Antares (1 fisiere returnate pentru acest CWE).

---

Dupa triaj, adauga in `baseline.json` ce ai reparat sau ce e fals-pozitiv:
`[{"file_path": "cale/fisier.php", "cwe": "CWE-89"}]`  — foloseste `"*"` pentru tot fisierul.
