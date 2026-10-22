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
