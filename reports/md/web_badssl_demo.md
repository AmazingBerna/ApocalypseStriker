# Report Automatico di VAPT Web

**Target analizzato:** https://badssl.com/  
**Data e ora:** 2026-10-22 10:34  
**Attività:** VAPT web - Vulnerability Assessment (ricognizione passiva, sola lettura)  
**Host:** badssl.com  
**Stato HTTP:** 200  
**Strumento:** ApocalypseStriker recon (sola lettura, libreria standard)

---

## Ricognizione passiva (Vulnerability Assessment)

Dati che il server dichiara da sé a una normale richiesta HTTP(S): nessun payload inviato, nessuna sollecitazione del bersaglio.

### Tecnologie esposte

| Header | Valore |
|---|---|
| server | nginx/1.10.3 (Ubuntu) |

### Configurazione TLS

| Voce | Valore |
|---|---|
| Protocollo | TLSv1.2 |
| Cifrario | ECDHE-RSA-AES128-GCM-SHA256 |
| Emittente certificato | Let's Encrypt |
| Scadenza certificato | Dec 28 20:02:55 2026 GMT (tra 67 giorni) |


---

## Tabella dei rischi (Rischio = Impatto x Probabilità)

Finding della ricognizione, valutati con lo stesso modello della serie e ordinati dal rischio più alto. Impatto e probabilità su scala 1-5, rischio da 1 a 25 (16-25 = Critico, 10-15 = Alto, 5-9 = Medio, 1-4 = Basso).

### Riepilogo per livello

| Livello | Finding |
|---|---:|
| Critico | 0 |
| Alto | 0 |
| Medio | 2 |
| Basso | 5 |
| Informativo (non valutati) | 0 |

### Matrice di rischio

Ogni cella riporta il punteggio (I x P) e, in grassetto, quanti finding vi ricadono.

| Impatto \ Probabilità | 1 Rara | 2 Improbabile | 3 Possibile | 4 Probabile | 5 Quasi certa |
|---|---|---|---|---|---|
| **5 Critico** | 5 M | 10 A | 15 A | 20 C | 25 C |
| **4 Alto** | 4 B | 8 M | 12 A | 16 C | 20 C |
| **3 Moderato** | 3 B | 6 M | 9 M · **2** | 12 A | 15 A |
| **2 Basso** | 2 B | 4 B · **2** | 6 M | 8 M | 10 A |
| **1 Trascurabile** | 1 B | 2 B · **3** | 3 B | 4 B | 5 M |

Legenda: C = Critico, A = Alto, M = Medio, B = Basso.

### Elenco dei finding

| # | OWASP | Finding | URL | Impatto | Probabilità | Rischio | Livello | Evidenza | Dettaglio |
|---:|---|---|---|---:|---:|---:|---|---|---|
| 1 | A05:2021 - Security Misconfiguration | Header mancante: strict-transport-security | https://badssl.com/ | 3 | 3 | **9** | Medio | assente nella risposta: strict-transport-security | HSTS assente: senza di esso un attaccante può forzare il traffico su HTTP in chiaro (downgrade/MITM). |
| 2 | A05:2021 - Security Misconfiguration | Header mancante: content-security-policy | https://badssl.com/ | 3 | 3 | **9** | Medio | assente nella risposta: content-security-policy | CSP assente: manca la principale difesa contro l'esecuzione di script iniettati (XSS). |
| 3 | A05:2021 - Security Misconfiguration | Header mancante: x-content-type-options | https://badssl.com/ | 2 | 2 | **4** | Basso | assente nella risposta: x-content-type-options | Manca 'nosniff': il browser può interpretare risorse con un tipo diverso da quello dichiarato. |
| 4 | A05:2021 - Security Misconfiguration | Header mancante: x-frame-options | https://badssl.com/ | 2 | 2 | **4** | Basso | assente nella risposta: x-frame-options | Manca la protezione anti-clickjacking (X-Frame-Options o CSP frame-ancestors). |
| 5 | A05:2021 - Security Misconfiguration | Header mancante: referrer-policy | https://badssl.com/ | 1 | 2 | **2** | Basso | assente nella risposta: referrer-policy | Referrer-Policy assente: possibile fuga di informazioni di provenienza verso siti terzi. |
| 6 | A05:2021 - Security Misconfiguration | Header mancante: permissions-policy | https://badssl.com/ | 1 | 2 | **2** | Basso | assente nella risposta: permissions-policy | Permissions-Policy assente: nessun limite esplicito a funzionalità del browser (camera, geolocalizzazione...). |
| 7 | A05:2021 - Security Misconfiguration | Divulgazione tecnologia: server | https://badssl.com/ | 1 | 2 | **2** | Basso | server: nginx/1.10.3 (Ubuntu) | Header rivela tecnologia e versione del server: facilita a un attaccante la ricerca di exploit mirati. |


---

## Note metodologiche

Per ogni finding **Rischio = Impatto x Probabilità** (scala 1-5, punteggio 1-25). Soglie: 16-25 = Critico, 10-15 = Alto, 5-9 = Medio, 1-4 = Basso.

| Valore | Impatto (danno se sfruttato) | Probabilità (verosimiglianza) |
|---:|---|---|
| 1 | Trascurabile | Rara |
| 2 | Basso | Improbabile |
| 3 | Moderato | Possibile |
| 4 | Alto | Probabile |
| 5 | Critico | Quasi certa |

La ricognizione è **passiva**: legge header, cookie e TLS come farebbe un browser, senza inviare payload. I valori sono euristici (definiti in `apocalypsescan_app/config.py`, blocco VAPT web) e **non sostituiscono una verifica manuale**. Il penetration testing attivo (OWASP ZAP) è una fase separata, soggetta a una conferma dedicata.
