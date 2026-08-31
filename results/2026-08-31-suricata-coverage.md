# Acoperirea semnaturilor ET Open pe DVRA (M1 preliminar)

Data: 2026-08-31
Senzor: Suricata 7.0.3, ET Open, subset web (8088 reguli)
Interfata: bridge Docker br-4b546cd1525f
HOME_NET=[172.19.0.3/32] (containerul aplicatiei), EXTERNAL_NET=any
Tinta: DVRA @ d32d0997, 172.19.0.3:8091

## Rezultat

| payload trimis | detectat |
|---|---|
| path traversal (/etc/passwd in URI) | DA - "ET WEB_SERVER /etc/passwd Detected in URI" |
| SQLi (UNION SELECT NULL) | NU |
| SQLi (OR '1'='1) | NU |
| command injection (;id) | NU |
| command injection (\|whoami) | NU |

## Cauza, verificata in sursa regulilor

Regulile ET Open pentru SQLi sunt legate de exploit-uri si produse
specifice, nu de clasa de atac. Exemple din web-only.rules:

- sid 2035104: cere POST la /portal/ cu "softwareUpdate/getSoftwareUpdates"
  in corp - semnatura pentru CVE-2020-3984 (VMware SD-WAN), nu SQLi generic.
- sid 2009985: cauta UNION SELECT dupa "USER" pe portul 21 (FTP).

Niciuna nu potriveste un UNION SELECT intr-un GET catre o aplicatie web
oarecare. Regula de path traversal se aprinde tocmai pentru ca e un tipar
generic ("/etc/passwd in URI"), nelegat de un CVE.

## Consecinta pentru teza

Un IDS bazat pe semnaturi detecteaza exploit-uri CUNOSCUTE, nu tehnici de
atac. Payload-uri valide impotriva unei aplicatii pe care regulile nu o
cunosc trec nedetectate. Aceasta e justificarea pentru corelarea cu analiza
de cod: IDS-ul singur nu vede majoritatea atacurilor din acest set.

M1 asteptat pe cele 6 pozitive: predominant NEDETECTAT prin semnaturi.
Aceasta NU e o eroare de configurare - mecanismul functioneaza (traversal se
aprinde). E o limitare a metodei bazate pe semnaturi.

## Limitari

- Un singur set de reguli (ET Open). Un set comercial ar putea diferi.
- Payload-uri de test simple; unele reguli cer contexte specifice care ar
  putea fi indeplinite de payload-uri mai elaborate.
- Nu s-a incercat scrierea de reguli custom pentru aplicatie - ar contrazice
  scopul, care e sa masor acoperirea semnaturilor GENERICE.
