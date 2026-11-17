# Modello di rischio: rischio = impatto x probabilità, entrambi su scala 1-5 (punteggio 1-25).
# Impatto: danno se la debolezza viene sfruttata. Probabilità: verosimiglianza che accada,
# considerando esposizione in rete, facilità di sfruttamento e disponibilità di exploit/patch.
IMPACT_SCALE = {1: "Trascurabile", 2: "Basso", 3: "Moderato", 4: "Alto", 5: "Critico"}
PROBABILITY_SCALE = {1: "Rara", 2: "Improbabile", 3: "Possibile", 4: "Probabile", 5: "Quasi certa"}

# (punteggio minimo, livello), dal più alto al più basso
RISK_THRESHOLDS = [(16, "Critico"), (10, "Alto"), (5, "Medio"), (1, "Basso")]

# porta: (servizio, impatto, probabilità, motivazione)
RISKY_SERVICES = {
    21: ("FTP", 3, 3, "Protocollo non cifrato: credenziali e dati trasmessi in chiaro."),
    23: ("Telnet", 5, 3, "Protocollo non cifrato e obsoleto: accesso remoto senza alcuna cifratura."),
    25: ("SMTP", 2, 2, "Servizio di posta; verificare se il banner espone informazioni di sistema."),
    69: ("TFTP", 4, 3, "Trasferimento file senza autenticazione, spesso usato per attacchi su dispositivi di rete."),
    110: ("POP3", 3, 2, "Se non incapsulato in TLS, credenziali trasmesse in chiaro."),
    135: ("MSRPC", 3, 3, "Servizio Windows spesso bersaglio di exploit di rete."),
    139: ("NetBIOS", 3, 3, "Servizio legacy Windows, superficie di attacco per enumerazione."),
    143: ("IMAP", 3, 2, "Se non incapsulato in TLS, credenziali trasmesse in chiaro."),
    445: ("SMB", 5, 3, "Storicamente bersaglio di exploit critici (es. EternalBlue); verificare versione e patch."),
    512: ("rexec", 5, 3, "Servizio remoto legacy non cifrato."),
    513: ("rlogin", 5, 3, "Servizio remoto legacy non cifrato."),
    514: ("rsh", 5, 3, "Servizio remoto legacy non cifrato."),
    1433: ("MSSQL", 4, 2, "Database esposto in rete: verificare autenticazione e accesso da soli host autorizzati."),
    1521: ("Oracle DB", 4, 2, "Database esposto in rete: verificare autenticazione e accesso da soli host autorizzati."),
    2049: ("NFS", 4, 2, "Condivisione file di rete: verificare permessi di export."),
    3306: ("MySQL/MariaDB", 4, 2, "Database esposto in rete: verificare che l'accesso non sia consentito da host non autorizzati."),
    3389: ("RDP", 5, 3, "Desktop remoto: bersaglio frequente di attacchi brute-force e credential stuffing."),
    5900: ("VNC", 5, 3, "Desktop remoto spesso con autenticazione debole o assente."),
    6379: ("Redis", 5, 3, "Spesso esposto senza autenticazione per configurazione di default."),
    8080: ("HTTP-alt", 3, 3, "Pannello o servizio web alternativo: verificare credenziali e necessità di esposizione."),
    9100: ("JetDirect/Stampa raw", 2, 3, "Porta di stampa raw spesso priva di autenticazione."),
    9200: ("Elasticsearch", 5, 3, "Spesso esposto senza autenticazione per configurazione di default."),
    27017: ("MongoDB", 5, 3, "Spesso esposto senza autenticazione per configurazione di default."),
}

LOW_RISK_DEFAULT = {
    22: ("SSH", 4, 1, "Accesso remoto cifrato; verificare comunque hardening (no root login, chiavi, Fail2Ban)."),
    53: ("DNS", 2, 2, "Risoluzione nomi; verificare che non sia un resolver aperto a Internet."),
    80: ("HTTP", 2, 2, "Verificare se esiste equivalente HTTPS e se sono presenti header di sicurezza."),
    443: ("HTTPS", 2, 1, "Verificare validità certificato e configurazione TLS."),
    631: ("IPP", 2, 1, "Servizio di stampa moderno."),
}

# Le tabelle sopra valgono per il TCP. Sull'UDP la stessa porta può essere un altro servizio
# (514/tcp è rsh, 514/udp è syslog): porta UDP -> (servizio, impatto, probabilità, motivazione)
RISKY_UDP_SERVICES = {
    69: ("TFTP", 4, 3, "Trasferimento file senza autenticazione, spesso usato per attacchi su dispositivi di rete."),
    111: ("rpcbind", 3, 2, "Espone l'elenco dei servizi RPC ed è usato per attacchi di amplificazione."),
    137: ("NetBIOS-NS", 3, 3, "Risoluzione nomi legacy di Windows: permette di enumerare host e utenti."),
    161: ("SNMP", 4, 3, "Con le community predefinite (public/private) espone, o permette di modificare, la configurazione."),
    1434: ("MSSQL Browser", 3, 2, "Rivela le istanze di SQL Server ed è usato per amplificazione."),
    1900: ("SSDP/UPnP", 3, 3, "Usato per attacchi di amplificazione; UPnP può aprire porte sul router."),
    2049: ("NFS", 4, 2, "Condivisione file di rete: verificare permessi di export."),
    11211: ("Memcached", 4, 3, "Senza autenticazione e con un fattore di amplificazione enorme."),
}

LOW_RISK_UDP_DEFAULT = {
    53: ("DNS", 2, 2, "Risoluzione nomi; verificare che non sia un resolver aperto a Internet."),
    67: ("DHCP", 2, 2, "Server DHCP: in una rete non sua può distribuire configurazioni sbagliate."),
    68: ("DHCP client", 1, 1, "Client DHCP: normale su una macchina che riceve l'indirizzo dalla rete."),
    123: ("NTP", 2, 2, "Sincronizzazione oraria; le versioni vecchie permettono amplificazione (monlist)."),
    500: ("IKE", 2, 1, "Negoziazione delle VPN IPsec; verificare che usi solo algoritmi robusti."),
    514: ("syslog", 2, 2, "Ricezione dei log in chiaro: chiunque può inviare log falsi."),
    1194: ("OpenVPN", 2, 1, "VPN cifrata."),
    5353: ("mDNS", 1, 2, "Annunci dei servizi sulla rete locale: rivela nomi e servizi della macchina."),
    51820: ("WireGuard", 1, 1, "VPN cifrata."),
}

# Servizio non presente nelle tabelle sopra: esposto ma di natura sconosciuta
UNKNOWN_SERVICE = (3, 2)

# Scansione UDP (--udp): quante porte UDP più comuni di default. È lenta, quindi non è -p-
UDP_TOP_PORTS = 50

# CVE trovate dagli script NSE di Nmap (corrispondenza solo sulla versione del banner)
NMAP_CVE = (4, 3)

# ssh-audit
SSH_NOTE_RISK = {"fail": (3, 2), "warn": (2, 2)}
SSH_CVE = (4, 3)
SSH_RECOMMENDATION = (3, 2)

# Trivy: impatto dalla gravità, probabilità dalla disponibilità di un fix
# (fix pubblico = vulnerabilità nota e documentata, più facile da sfruttare)
TRIVY_IMPACT = {"CRITICAL": 5, "HIGH": 4}
TRIVY_PROBABILITY_FIX = 3
TRIVY_PROBABILITY_NO_FIX = 2

# Lynis
LYNIS_WARNING = (3, 3)
LYNIS_SUGGESTION = (2, 2)

# Dati sulle minacce: la probabilità dei finding con CVE (Trivy, nmap-vuln, ssh-audit) viene
# dal catalogo CISA KEV (vulnerabilità sfruttate attivamente) e dal punteggio EPSS di FIRST
# (probabilità stimata di sfruttamento nei prossimi 30 giorni). I valori sopra restano il
# ripiego per le CVE che non compaiono in nessuna delle due fonti.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
THREAT_INTEL_MAX_AGE_HOURS = 24      # oltre questa età i file in cache vengono riscaricati
THREAT_INTEL_TIMEOUT = 60            # secondi per ogni download

KEV_PROBABILITY = 5
# (EPSS minimo, probabilità), dal più alto al più basso; sotto l'ultima soglia la probabilità è 1
EPSS_PROBABILITY = [(0.10, 4), (0.01, 3), (0.001, 2)]
EPSS_MIN_PROBABILITY = 1

# Ripiego per le CVE senza EPSS: probabilità dal vettore CVSS (Attack Vector, privilegi, interazione)
CVSS_PROBABILITY = {
    "network_unauth": 4,   # AV:N, PR:N, UI:N - sfruttabile da rete, senza credenziali né utente
    "network": 3,          # AV:N con altre condizioni
    "adjacent_local": 2,   # AV:A o AV:L
    "physical": 1,         # AV:P
}

# nmap-vuln deduce le CVE dal solo banner di versione: la probabilità non supera questo valore
NMAP_CVE_MAX_PROBABILITY = 4

# Trivy: le CVE MEDIUM e LOW diventano finding solo se sono nel KEV o hanno EPSS almeno pari a questo
TRIVY_PROMOTED_IMPACT = {"MEDIUM": 3, "LOW": 2}
TRIVY_PROMOTE_MIN_EPSS = 0.10

# Esposizione (esposizione.py). Un pacchetto che serve una porta aperta verso la rete, o che è
# una libreria caricata da quel servizio, ha CVE raggiungibili da chiunque arrivi alla porta:
# la probabilità sale di questo valore (fino a 5), se almeno una CVE si sfrutta da rete (AV:N)
EXPOSURE_PROBABILITY_BONUS = 1

# CVE di nmap-vuln che Trivy non trova nel pacchetto del servizio: per la distribuzione sono
# già corrette (backport) o non applicabili. Se nessuna è confermata, la probabilità scende qui
NMAP_CVE_UNCONFIRMED_PROBABILITY = 1


# ============================================================================
# VAPT web (ApocalypseStriker) - stesso modello: rischio = impatto x probabilità.
# I finding web portano in più la categoria OWASP Top 10 (2021).
# ============================================================================

# Categorie OWASP Top 10 (2021): sigla interna -> etichetta estesa nel report.
# L'elenco completo serve perché ZAP può etichettare un alert con qualsiasi categoria (tag OWASP_2021_Axx).
OWASP = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

# Ambiente dell'applicazione analizzata: dichiarato all'avvio (--env o prompt) e scritto nel report
WEB_AMBIENTI = ("sviluppo", "test", "staging", "produzione")

# Portata del Vulnerability Assessment passivo. Coperte: le categorie in cui recon.py trova
# debolezze di CONFIGURAZIONE leggendo risposte e handshake.
WEB_VA_COPERTE = {
    "A02": "configurazione TLS: protocolli accettati, validità e scadenza del certificato",
    "A05": "header di sicurezza mancanti o deboli, flag dei cookie, divulgazione di tecnologie",
    "A06": "versioni dichiarate nei banner con CVE note (NVD, KEV, EPSS)",
}
# Fuori portata: servono payload, cioè il penetration testing attivo (fase ZAP, rimandata).
# Non trovarle qui NON significa che l'applicazione ne sia priva.
WEB_VA_FUORI_PORTATA = {
    "A01": "controllo degli accessi: IDOR, accesso a funzioni o dati di altri utenti",
    "A03": "injection: SQL injection, XSS, command injection",
    "A04": "difetti di progettazione e di logica applicativa",
    "A07": "autenticazione e sessioni: bypass del login, brute force, gestione dei token",
    "A08": "integrità di software e dati: deserializzazione insicura",
    "A09": "logging e monitoraggio: non osservabili dall'esterno",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Header di sicurezza mancanti: header (minuscolo) -> (owasp, impatto, probabilità, motivazione).
# HSTS è pesato solo quando il sito è su HTTPS (vedi web_risk.py): su HTTP il browser lo ignora.
WEB_MISSING_HEADER = {
    "strict-transport-security": ("A05", 3, 3, "HSTS assente: senza di esso un attaccante può forzare il traffico su HTTP in chiaro (downgrade/MITM)."),
    "content-security-policy": ("A05", 3, 3, "CSP assente: manca la principale difesa contro l'esecuzione di script iniettati (XSS)."),
    "x-content-type-options": ("A05", 2, 2, "Manca 'nosniff': il browser può interpretare risorse con un tipo diverso da quello dichiarato."),
    "x-frame-options": ("A05", 2, 2, "Manca la protezione anti-clickjacking (X-Frame-Options o CSP frame-ancestors)."),
    "referrer-policy": ("A05", 1, 2, "Referrer-Policy assente: possibile fuga di informazioni di provenienza verso siti terzi."),
    "permissions-policy": ("A05", 1, 2, "Permissions-Policy assente: nessun limite esplicito a funzionalità del browser (camera, geolocalizzazione...)."),
}

# Header presenti ma deboli: (owasp, impatto, probabilità, motivazione), come sopra.
# HSTS: sotto i 6 mesi (soglia di Mozilla Observatory) la protezione dal downgrade scade presto;
# max-age=0 chiede al browser di dimenticare l'HSTS, quindi vale come assente.
WEB_HSTS_MIN_MAX_AGE = 15768000
WEB_HSTS_SHORT = ("A05", 2, 2, "HSTS con max-age inferiore a 6 mesi: tra una visita e l'altra il browser torna esposto al downgrade su HTTP.")
WEB_HSTS_DISABLED = ("A05", 3, 3, "HSTS con max-age assente o pari a 0: il browser non applica (o dimentica) l'obbligo di HTTPS.")

# CSP: sorgenti che in script-src (o default-src) annullano la difesa anti-XSS. Regole CSP3:
# 'unsafe-inline' è ignorato se c'è un nonce o un hash; *, http:, https:, data: sono ignorati
# con 'strict-dynamic'. 'unsafe-eval' non viene neutralizzato da nulla.
WEB_CSP_WILDCARD_SOURCES = ("*", "http:", "https:", "data:")
WEB_CSP_WEAK = ("A05", 3, 2, "CSP presente ma permissiva sugli script: un XSS iniettato verrebbe eseguito comunque.")
WEB_CSP_NO_SCRIPT_RULE = ("A05", 3, 2, "CSP senza script-src né default-src: gli script restano consentiti da qualunque sorgente.")

# Valori che rendono inefficaci header presenti
WEB_XCTO_WEAK = ("A05", 2, 2, "X-Content-Type-Options con valore diverso da 'nosniff': il browser lo ignora.")
WEB_XFO_WEAK = ("A05", 2, 2, "X-Frame-Options con valore non valido o obsoleto (ALLOW-FROM): i browser moderni lo ignorano, nessuna protezione anti-clickjacking.")
WEB_REFERRER_WEAK = ("A05", 1, 2, "Referrer-Policy 'unsafe-url': l'URL completo (percorso e parametri) viene inviato a ogni sito terzo, anche da HTTPS a HTTP.")

# Flag di sicurezza mancanti su un cookie: flag -> (owasp, impatto, probabilità, motivazione).
# 'secure' è pesato solo su HTTPS: su un sito HTTP il traffico è già in chiaro.
WEB_COOKIE_FLAG = {
    "secure": ("A05", 3, 3, "Cookie senza 'Secure': può essere trasmesso anche su HTTP in chiaro e intercettato."),
    "httponly": ("A05", 2, 3, "Cookie senza 'HttpOnly': leggibile da JavaScript, quindi esfiltrabile tramite XSS."),
    "samesite": ("A05", 2, 2, "Cookie senza 'SameSite': inviato anche nelle richieste cross-site (esposto a CSRF)."),
}

# Header che rivelano tecnologia/versione (Server, X-Powered-By...): aiutano il fingerprinting
WEB_TECH_DISCLOSURE = ("A05", 1, 2, "Header rivela tecnologia e versione del server: facilita a un attaccante la ricerca di exploit mirati.")

# Applicazione servita su HTTP (URL finale, dopo i redirect, in http://): nessuna cifratura.
# Vale anche per un https:// che reindirizza a http:// (downgrade).
WEB_NO_HTTPS = ("A02", 4, 3, "Applicazione servita su HTTP in chiaro: credenziali, cookie di sessione e dati viaggiano leggibili e modificabili da chiunque sia sul percorso di rete.")

# TLS: versioni del protocollo considerate deboli/obsolete
WEB_TLS_WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
WEB_TLS_OLD = ("A02", 4, 3, "Protocollo TLS obsoleto: vulnerabile ad attacchi noti; usare almeno TLS 1.2.")

# Certificato che non supera la validazione (scaduto, self-signed, hostname non corrispondente)
WEB_TLS_CERT_INVALID = ("A02", 4, 3, "Certificato TLS non valido o non attendibile: la connessione non offre garanzie di identità.")

# Certificato valido ma prossimo alla scadenza: avviso operativo, non una falla sfruttabile
WEB_TLS_CERT_EXPIRING_DAYS = 15
WEB_TLS_CERT_EXPIRING = ("A02", 2, 2, "Certificato TLS in scadenza a breve: pianificare il rinnovo per evitare disservizi.")

# Versioni note -> CVE (web/cve_nvd.py). Nome del prodotto nel banner (minuscolo) -> (produttore,
# prodotto) del CPE di NVD. Solo voci verificate su NVD il 22/10/2026 con una CVE nota: un CPE
# sbagliato non dà errore ma 0 CVE (nginx:nginx -> 0, f5:nginx -> 14 CVE per la 1.10.3).
WEB_TECH_CPE = {
    "nginx": ("f5", "nginx"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "apache": ("apache", "http_server"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
}
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"      # chiave facoltativa: alza il limite da 5 a 50 richieste ogni 30 s
NVD_PAUSE = (6.5, 0.7)               # secondi tra due richieste: senza chiave, con chiave
NVD_TIMEOUT = 60
NVD_CACHE_HOURS = 24                 # stessa versione non richiesta due volte in un giorno

# Impatto dalla gravità CVSS della CVE peggiore (come TRIVY_IMPACT); senza gravità, il default
WEB_CVE_IMPACT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
WEB_CVE_DEFAULT_IMPACT = 3
# Probabilità: da KEV/EPSS/CVSS (threat_intel.assess_cves), con questo ripiego senza dati.
# La versione viene dal solo banner, come per nmap-vuln: non supera WEB_CVE_MAX_PROBABILITY.
WEB_CVE_PROBABILITY = 3
WEB_CVE_MAX_PROBABILITY = 4
# Banner di un pacchetto di distribuzione (es. "nginx/1.10.3 (Ubuntu)"): le distribuzioni
# applicano le patch di sicurezza senza cambiare il numero di versione (backport), quindi
# molte CVE elencate sono probabilmente già corrette. La probabilità scende a questo tetto.
WEB_CVE_BACKPORT_MAX_PROBABILITY = 2
WEB_DISTRO_MARKERS = ("ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "rocky",
                      "almalinux", "suse", "amzn")


# ============================================================================
# ZAP (penetration testing) - mappatura degli alert sul modello rischio = impatto x probabilità.
# Mappatura confermata sugli alert reali di ZAP 2.17 (badssl.com).
# ============================================================================

# impatto <- risk di ZAP ("Informational" non entra nel calcolo: diventa finding informativo)
ZAP_RISK_IMPACT = {"High": 4, "Medium": 3, "Low": 2}

# probabilità <- confidence di ZAP (quanto ZAP è sicuro che l'alert sia reale)
ZAP_CONFIDENCE_PROBABILITY = {"Confirmed": 4, "User Confirmed": 4, "High": 3, "Medium": 2, "Low": 1}

# alert con questa confidence vengono scartati (ZAP li considera già falsi positivi)
ZAP_SKIP_CONFIDENCE = ("False Positive",)

# indirizzo di default del daemon ZAP (Docker sul PC host, porta interna = esterna)
ZAP_API_DEFAULT = "http://127.0.0.1:8090"


# ============================================================================
# Penetration testing ATTIVO nativo (web/pentest.py) - fase a sé, sola libreria
# standard, nessuna dipendenza esterna (gira anche su un Raspberry).
#
# A differenza del Vulnerability Assessment passivo (recon.py, sola lettura),
# questa fase INVIA payload nei punti di input (parametri dell'URL e campi dei
# form) per CONFERMARE vulnerabilità sfruttabili. È protetta da un secondo
# consenso dedicato (pentest.confirm_pentest) e NON è distruttiva: payload di
# sola lettura, tetto di richieste, niente DROP/DELETE/flood, niente scrittura
# di dati. Stesso modello di rischio: rischio = impatto x probabilità.
#
# La probabilità dei finding attivi è alta perché il test CONFERMA lo
# sfruttamento (non è un semplice indizio come nel passivo): per questo molti
# valgono 4-5. L'impatto resta legato al danno della singola classe.
# ============================================================================

# --- Crawler di scoperta (spider leggero, stesso host, http/https) ---
PT_CRAWL_MAX_PAGES = 40        # numero massimo di pagine visitate dallo spider
PT_CRAWL_MAX_DEPTH = 3         # profondità massima dei link interni seguiti
PT_CRAWL_SAME_HOST = True      # non esce mai dall'host del bersaglio

# --- Budget e tempi (protezione del bersaglio: mai un flood) ---
PT_MAX_REQUESTS = 800          # tetto totale di richieste dell'intera fase attiva
PT_MAX_POINTS = 150            # punti di input massimi testati (parametri + campi form)
PT_TIMEOUT = 12                # secondi di timeout per ogni richiesta
PT_RETRY_TIMEOUT = 1           # ritenta una volta solo se scade il timeout
PT_DELAY = 0.0                 # pausa tra richieste in secondi (>0 per rallentare di proposito)
PT_USER_AGENT = "ApocalypseStriker-pentest/1.0 (autorizzato)"

# --- Rilevamento time-based (SQLi/Command Injection) ---
# Si conferma solo se la risposta col payload "lento" supera la soglia MENTRE una
# richiesta di controllo (payload con ritardo 0) resta sotto: così un bersaglio
# genericamente lento non produce falsi positivi.
PT_TIME_DELAY = 5              # secondi di ritardo che il payload chiede al server
PT_TIME_THRESHOLD = 4.0        # oltre questi secondi la risposta è considerata "ritardata"
PT_MAX_TIME_PROBES = 40        # quante sonde time-based al massimo in una scansione (sono lente)
PT_BODY_LIMIT = 300 * 1024     # byte del corpo letti per ogni risposta (confronto differenziale)

# Differenza minima (0-1, su SequenceMatcher) perché due risposte siano "diverse":
# serve al boolean-based SQLi (condizione vera ~ pagina base, condizione falsa diversa)
PT_DIFF_RATIO = 0.06

# --- Punteggi dei finding attivi: (owasp, impatto, probabilità, motivazione) ---
PT_SQLI_ERROR = ("A03", 5, 5,
    "SQL injection confermata: un apice nel parametro provoca un errore SQL del database "
    "non presente nella risposta di base. L'input finisce in una query senza parametrizzazione: "
    "permette lettura/alterazione dei dati e spesso l'accesso completo al database.")
PT_SQLI_BOOLEAN = ("A03", 5, 4,
    "SQL injection (boolean-based): una condizione sempre vera restituisce la pagina di base, "
    "una sempre falsa una pagina diversa. La query è influenzabile dall'input: dati estraibili "
    "un bit alla volta, anche senza messaggi di errore.")
PT_SQLI_TIME = ("A03", 5, 5,
    "SQL injection (time-based): un payload che chiede al database di attendere ritarda la "
    "risposta in modo misurabile, mentre la richiesta di controllo resta veloce. La query "
    "esegue input arbitrario: estrazione dati 'alla cieca' confermata.")
PT_XSS_REFLECTED = ("A03", 4, 4,
    "Cross-Site Scripting riflesso: un marcatore con caratteri speciali (< > \" ') torna "
    "nella risposta HTML senza codifica, in un contesto eseguibile. Un attaccante può far "
    "eseguire script nel browser della vittima (furto di sessione, azioni per suo conto).")
PT_CMDI = ("A03", 5, 5,
    "Command injection: l'input viene passato a una shell del sistema. Confermata facendo "
    "attendere il server (ritardo misurato) o facendogli restituire un marcatore prodotto da "
    "un comando: esecuzione di comandi arbitrari sul server.")
PT_SSTI = ("A03", 5, 5,
    "Server-Side Template Injection: un'espressione del motore di template (es. {{7*7}}) viene "
    "valutata e restituisce il risultato del calcolo. Porta tipicamente all'esecuzione di codice "
    "sul server.")
PT_PATH_TRAVERSAL = ("A01", 4, 5,
    "Path traversal / Local File Inclusion: con '../' il parametro legge un file di sistema "
    "(es. /etc/passwd) fuori dalla cartella prevista. Espone file arbitrari del server, "
    "configurazioni e segreti inclusi.")
PT_OPEN_REDIRECT = ("A01", 2, 4,
    "Open redirect: il parametro controlla la destinazione di un redirect verso un host esterno "
    "arbitrario. Utile per phishing credibile (il link parte dal dominio fidato) e per aggirare "
    "alcune protezioni.")
PT_SSRF = ("A10", 4, 3,
    "Possibile Server-Side Request Forgery: il parametro sembra far compiere al server una "
    "richiesta verso un URL fornito dall'utente. Va confermato con un endpoint di callback "
    "controllato: qui è segnalato come candidato da verificare a mano.")
PT_EXPOSED_FILE = ("A05", 4, 5,
    "File sensibile esposto: una risorsa che non dovrebbe essere pubblica (es. .env, .git, "
    "copia di backup, elenco directory) è scaricabile. Spesso contiene credenziali, codice "
    "sorgente o dati riservati.")

# --- Firme di errore SQL per DBMS (rilevamento error-based) ---
# (regex, etichetta del motore). Confermano l'iniezione solo se COMPAIONO con il
# payload e NON erano già nella risposta di base.
PT_SQL_ERROR_SIGNATURES = (
    (r"you have an error in your sql syntax", "MySQL/MariaDB"),
    (r"warning:\s*mysqli?_", "MySQL (PHP)"),
    (r"mysql_fetch_(array|assoc|row|object)", "MySQL (PHP)"),
    (r"com\.mysql\.jdbc", "MySQL (JDBC)"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft (ole db|sql server|odbc)", "MSSQL"),
    (r"unterminated quoted string at or near", "PostgreSQL"),
    (r"pg_query\(\)|pg_exec\(\)", "PostgreSQL"),
    (r"psql:.*error", "PostgreSQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"sqlite3?\.(operational|programming)error", "SQLite"),
    (r"sqlite_error|no such column", "SQLite"),
    (r"syntax error at or near", "SQL (generico)"),
)

# --- Firme che confermano la lettura di un file di sistema (path traversal) ---
# (regex, descrizione del file letto)
PT_LFI_SIGNATURES = (
    (r"root:.*:0:0:", "/etc/passwd (utenti Unix)"),
    (r"\[(extensions|fonts|mci extensions)\]", "win.ini (Windows)"),
    (r"for 16-bit app support", "win.ini (Windows)"),
)

# --- Firme di contenuto dei file sensibili esposti ---
# percorso -> (regex di conferma del contenuto, descrizione)
PT_EXPOSED_SIGNATURES = {
    "/.env": (r"(?im)^\s*[A-Z0-9_]+\s*=", "variabili d'ambiente (possibili credenziali)"),
    "/.git/HEAD": (r"ref:\s*refs/", "repository Git (codice sorgente e cronologia)"),
    "/.git/config": (r"\[core\]", "configurazione Git del repository"),
    "/.svn/entries": (r"(?s)\d+\s", "repository Subversion"),
    "/config.php.bak": (r"<\?php", "copia di backup del sorgente PHP"),
    "/.htpasswd": (r":\$(apr1|2y|1)\$", "credenziali .htpasswd"),
    "/server-status": (r"Apache Server Status", "pagina di stato Apache (mod_status)"),
}
# Risorse da sondare (oltre a quelle con firma sopra); confermate dallo status 200 + firma
PT_EXPOSED_EXTRA_PATHS = ("/backup/", "/backup.zip", "/backup.sql", "/db.sql",
                          "/dump.sql", "/.git/", "/.DS_Store", "/phpinfo.php")

# Nomi di parametro che tipicamente controllano un redirect o un URL di destinazione
PT_REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_uri", "redirect_url", "return",
                      "returnurl", "return_url", "dest", "destination", "continue", "to",
                      "goto", "out", "link", "target", "r", "u")
# Host esterno usato come sonda per open redirect / SSRF (dominio di esempio riservato IANA)
PT_PROBE_HOST = "example.org"
