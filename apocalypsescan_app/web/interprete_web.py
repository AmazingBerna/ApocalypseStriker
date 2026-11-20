"""interprete_web.py - Interprete a regole del report web: lo spiega in linguaggio semplice.

Stessa impostazione dell'interprete host: deterministico, solo regole fisse applicate ai
campi del modello, nessuna dipendenza esterna e nessun modello di linguaggio. Lavora sul
modello di web_report.build_web_model (meta, tecnologie, tls, findings) e non aggiunge
fatti che non siano nel report: le parti variabili dei testi (parametro, cookie, URL,
CVE...) vengono solo dai campi del finding.

interpreta_web(model) restituisce una lettura strutturata: verdetto, conteggi per livello,
punti chiave, priorità e, per ogni finding valutato, tre voci:
    cosa_significa   la causa tecnica, in una o due frasi
    come_attaccano   l'attacco concreto e cosa ottiene l'attaccante
    cosa_fare        la correzione, concisa e azionabile
più il "perché" del livello di rischio (impatto x probabilità) e i limiti della lettura.

Il TIPO di vulnerabilità si ricava dal finding:
  - penetration testing attivo: dalla classe nella key pt-<classe>-... (sqli, xss, cmdi,
    ssti, lfi, redirect, ssrf, exposed, csrf, idor). La key non entra nel modello, ma è
    incorporata nell'id (pentest-<host>-pt-<classe>-...): si legge da lì;
  - finding passivi: dalla fonte (header, cookie, tls, http, cve) e dalla voce.
I tipi senza finding nel modello (es. CSRF e IDOR, il cui rilevamento non c'è ancora)
semplicemente non compaiono; i finding di un tipo senza regola usano la loro motivazione
e un testo generico per la categoria OWASP.

Uso (da web_report, opzione --interpreta):
    lettura = interpreta_web(model)
    percorso = salva(lettura, nome_report)        # reports/md/<nome>_interpretazione.md
    print_interpretazione(lettura, percorso)
"""
import re
import textwrap
from typing import Callable, NamedTuple

from .. import menu_stile as st
from .esito_pt import esito_di, fonte_di
from ..config import (
    EPSS_PROBABILITY, IMPACT_SCALE, OWASP, PROBABILITY_SCALE, RISK_THRESHOLDS,
    WEB_TECH_CPE, WEB_VA_COPERTE, WEB_VA_FUORI_PORTATA,
)
from ..percorsi import SUFFISSO_INTERPRETAZIONE, percorso_output, scrivi
from ..report_model import _slug

MAX_PRIORITA = 5

# Livelli valutati, dal più grave (gli stessi delle soglie di rischio)
LIVELLI = tuple(livello for _, livello in RISK_THRESHOLDS)

# Cosa fare in base al livello di rischio
AZIONE_LIVELLO = {
    "Critico": "Intervieni subito: è tra i problemi più seri del report.",
    "Alto": "Da correggere a breve, subito dopo i finding critici.",
    "Medio": "Da pianificare: non è urgente, ma non va trascurato.",
    "Basso": "Miglioramento da fare quando possibile.",
}

# L'ultima voce dei limiti, sempre presente: resta nel file, non a terminale
AVVERTENZA_FINALE = ("Questa lettura applica regole fisse ai dati del report: non sostituisce la "
                     "verifica di un esperto, e l'assenza di un finding non garantisce che il "
                     "problema non ci sia.")


# ==========================================================================
# Schede per tipo di vulnerabilità
# ==========================================================================

class Scheda(NamedTuple):
    """Le tre voci di un tipo di vulnerabilità. Ogni voce è un testo con segnaposto
    ({parametro}, {cookie}, {url}, {dettaglio}, {servizio}, {cve}) riempiti dai campi
    del finding, oppure una funzione (finding, campi) -> testo."""
    nome: str
    cosa_significa: object
    come_attaccano: object
    cosa_fare: object


def _significa_certificato(f, campi):
    return (f"{f['reason']} Il browser non può verificare di parlare con il server legittimo.")


def _attacco_cve(f, campi):
    testo = ("Per le CVE note esistono spesso exploit pubblici: l'attaccante li cerca per la "
             "versione rilevata e li lancia contro il sito, senza dover scoprire nulla di nuovo.")
    if f.get("kev"):
        testo += " Almeno una di queste CVE è nel catalogo CISA KEV: è già usata in attacchi reali."
    return testo


SCHEDE = {
    # --- Penetration testing attivo (classe nella key pt-<classe>-...) ---
    "sqli": Scheda(
        "SQL injection",
        "Il valore del parametro {parametro} viene inserito nella query SQL come testo, senza "
        "query parametrizzate: il database lo esegue come parte del comando.",
        "L'attaccante scrive nel parametro frammenti SQL (es. ' OR 1=1 --) e legge intere tabelle "
        "(utenti, password, dati personali), le modifica o le cancella; spesso aggira anche il login.",
        "Usa query parametrizzate (prepared statement) o l'ORM per ogni accesso al database, senza "
        "mai concatenare input nelle query; dai all'utenza del database solo i permessi necessari."),
    "xss": Scheda(
        "Cross-Site Scripting (XSS)",
        "Il parametro {parametro} torna nella pagina HTML senza codifica: il browser interpreta "
        "come codice ciò che l'utente ha scritto.",
        "L'attaccante prepara un link con uno script nel parametro e lo fa aprire alla vittima: lo "
        "script gira nel suo browser con la sua sessione, ruba i cookie leggibili e agisce al suo posto.",
        "Codifica l'output in base al contesto (HTML, attributo, JavaScript) con le funzioni del "
        "framework o del template; aggiungi una Content-Security-Policy restrittiva come seconda difesa."),
    "cmdi": Scheda(
        "Command injection",
        "Il parametro {parametro} finisce in un comando della shell del server senza filtri: "
        "caratteri come ; | && permettono di aggiungere altri comandi.",
        "L'attaccante accoda al valore un proprio comando e lo esegue sul server con i permessi "
        "dell'applicazione: legge file e segreti, installa malware, si sposta nella rete interna.",
        "Non passare input alla shell: usa le API del linguaggio o un processo con lista di "
        "argomenti (senza shell), e accetta solo valori di una lista bianca."),
    "ssti": Scheda(
        "Server-Side Template Injection",
        "Il parametro {parametro} viene inserito nel testo del template e valutato dal motore di "
        "template, invece di essere passato come semplice dato.",
        "L'attaccante inserisce espressioni del motore di template che risalgono agli oggetti interni "
        "fino a eseguire codice sul server: legge i segreti di configurazione e prende il controllo "
        "dell'applicazione.",
        "Passa l'input al template solo come variabile, mai come parte del template; se gli utenti "
        "devono scrivere template, usa il motore in modalità sandbox."),
    "lfi": Scheda(
        "Path traversal / Local File Inclusion",
        "Il parametro {parametro} serve a costruire il percorso di un file senza limitarlo alla "
        "cartella prevista: con ../ si esce dalla cartella.",
        "L'attaccante chiede file del sistema e dell'applicazione (/etc/passwd, .env, configurazioni, "
        "codice sorgente) e ottiene password, chiavi API e informazioni per gli attacchi successivi.",
        "Non usare l'input come percorso: associa gli identificativi a una lista di file ammessi, "
        "oppure normalizza il percorso e verifica che resti dentro la cartella consentita."),
    "redirect": Scheda(
        "Open redirect",
        "Il parametro {parametro} decide la destinazione di un redirect e accetta qualunque host "
        "esterno.",
        "L'attaccante diffonde un link che inizia con il tuo dominio ma porta a una sua copia della "
        "pagina di login: la vittima si fida del dominio e gli consegna le credenziali.",
        "Accetta solo percorsi interni relativi o destinazioni in una lista bianca; per tutto il "
        "resto reindirizza a una pagina fissa."),
    "ssrf": Scheda(
        "Server-Side Request Forgery (candidato)",
        "Il parametro {parametro} sembra contenere un URL che il server va a scaricare da sé: è un "
        "candidato SSRF, non ancora confermato.",
        "Se è sfruttabile, l'attaccante fa contattare al server indirizzi interni non raggiungibili "
        "da Internet (pannelli di amministrazione, database, servizio di metadati del cloud) e ne "
        "legge le risposte.",
        "Verifica a mano con un endpoint di callback controllato; se è confermato, ammetti solo "
        "domini di una lista bianca, blocca gli indirizzi interni e privati e non seguire i redirect."),
    "exposed": Scheda(
        "File sensibile esposto",
        "La risorsa {url} è scaricabile da chiunque, ma non dovrebbe essere pubblica (configurazione, "
        "repository .git, backup o elenco di una cartella).",
        "L'attaccante la scarica direttamente: dai file di configurazione ottiene password e chiavi, "
        "da .git ricostruisce il codice sorgente, dai backup i dati del database.",
        "Togli la risorsa dalla cartella pubblica o bloccane l'accesso nel server web; se conteneva "
        "segreti, considerali compromessi e cambiali."),
    "csrf": Scheda(
        "Cross-Site Request Forgery (CSRF)",
        "L'azione su {url} viene eseguita in base ai soli cookie di sessione, senza un token "
        "anti-CSRF che provi che la richiesta parte dall'applicazione.",
        "L'attaccante mette in una sua pagina un form nascosto che invia la richiesta: quando la "
        "vittima autenticata la visita, il browser allega i cookie e l'azione (cambio di email o "
        "password, pagamento) parte a suo nome.",
        "Aggiungi un token anti-CSRF legato alla sessione a ogni form e richiesta che modifica dati, "
        "verificalo sul server e imposta i cookie di sessione con SameSite=Lax o Strict."),
    "idor": Scheda(
        "Insecure Direct Object Reference (IDOR)",
        "L'applicazione usa l'identificativo nel parametro {parametro} per restituire un oggetto "
        "senza verificare che appartenga all'utente che lo chiede.",
        "L'attaccante cambia l'identificativo (es. id=1001 in id=1002) e legge o modifica i dati di "
        "altri utenti: documenti, ordini, profili.",
        "Controlla sul server, a ogni richiesta, che l'oggetto appartenga all'utente autenticato o "
        "che lui abbia i permessi per vederlo; non fidarti dell'identificativo inviato dal client."),

    # --- Vulnerability Assessment passivo: header di sicurezza ---
    "csp": Scheda(
        "Content-Security-Policy assente o debole",
        "La pagina non ha una Content-Security-Policy che limiti gli script (assente o troppo "
        "permissiva): il browser esegue qualunque script si trovi nella pagina.",
        "Se l'attaccante riesce a iniettare uno script (XSS), niente ne blocca l'esecuzione: ruba la "
        "sessione, mostra un falso login o agisce a nome dell'utente.",
        "Imposta una CSP con script-src limitato alle tue sorgenti (meglio con nonce o hash), senza "
        "'unsafe-inline', 'unsafe-eval' o *; provala prima con Content-Security-Policy-Report-Only."),
    "hsts": Scheda(
        "HSTS assente o debole",
        "Manca HSTS (o ha durata nulla o breve): il browser non è obbligato a usare sempre HTTPS "
        "per questo sito.",
        "Su una rete controllata dall'attaccante (es. Wi-Fi pubblico) la prima richiesta in HTTP "
        "viene intercettata e la vittima resta in HTTP (SSL stripping): credenziali e cookie "
        "viaggiano in chiaro.",
        "Invia Strict-Transport-Security: max-age=31536000; includeSubDomains su tutte le risposte "
        "HTTPS."),
    "xfo": Scheda(
        "Protezione anti-clickjacking assente",
        "La pagina non vieta al browser di mostrarla dentro un frame di un altro sito "
        "(X-Frame-Options o CSP frame-ancestors assenti o non validi).",
        "Clickjacking: l'attaccante carica la pagina in un frame invisibile sopra la propria e "
        "induce la vittima a cliccare pulsanti reali (conferme, cambi di impostazioni) credendo di "
        "cliccare altro.",
        "Invia X-Frame-Options: DENY (o SAMEORIGIN) oppure, meglio, "
        "Content-Security-Policy: frame-ancestors 'self'."),
    "xcto": Scheda(
        "X-Content-Type-Options assente o non valido",
        "Manca X-Content-Type-Options: nosniff (o ha un valore non valido): il browser può "
        "\"indovinare\" il tipo di un file invece di rispettare quello dichiarato.",
        "L'attaccante carica un file all'apparenza innocuo (immagine, testo) che contiene script: "
        "il browser lo interpreta come HTML o JavaScript e lo esegue.",
        "Invia X-Content-Type-Options: nosniff su tutte le risposte e dichiara sempre il "
        "Content-Type corretto."),
    "referrer": Scheda(
        "Referrer-Policy assente o permissiva",
        "La Referrer-Policy è assente o permissiva: l'indirizzo della pagina può essere inviato ai "
        "siti esterni collegati o inclusi.",
        "Se negli URL ci sono token, identificativi o dati personali, l'attaccante li raccoglie dai "
        "log di un sito esterno linkato o di una risorsa inclusa.",
        "Invia Referrer-Policy: strict-origin-when-cross-origin (o no-referrer) e non mettere dati "
        "sensibili negli URL."),
    "permissions": Scheda(
        "Permissions-Policy assente",
        "Manca la Permissions-Policy: la pagina non limita in modo esplicito le funzioni del browser "
        "(fotocamera, microfono, posizione) per sé e per i contenuti inclusi.",
        "Uno script o un frame di terze parti compromesso (o iniettato) può chiedere l'accesso a "
        "quelle funzioni presentandosi con il nome del tuo sito.",
        "Invia Permissions-Policy disattivando ciò che non usi, es. camera=(), microphone=(), "
        "geolocation=()."),

    # --- Cookie ---
    "cookie_secure": Scheda(
        "Cookie senza Secure",
        "Il cookie {cookie} non ha l'attributo Secure: il browser può inviarlo anche su connessioni "
        "HTTP non cifrate.",
        "Su una rete intercettata l'attaccante provoca una richiesta HTTP verso il sito e legge il "
        "cookie in chiaro; se è di sessione, entra nell'account della vittima.",
        "Imposta Secure su tutti i cookie e servi il sito solo su HTTPS."),
    "cookie_httponly": Scheda(
        "Cookie senza HttpOnly",
        "Il cookie {cookie} non ha l'attributo HttpOnly: è leggibile da JavaScript nella pagina.",
        "Con un XSS l'attaccante legge il cookie e lo invia a un proprio server; se è di sessione, "
        "lo usa per entrare nell'account della vittima.",
        "Imposta HttpOnly su tutti i cookie che JavaScript non deve leggere, sempre su quelli di "
        "sessione."),
    "cookie_samesite": Scheda(
        "Cookie senza SameSite",
        "Il cookie {cookie} non ha l'attributo SameSite: il browser lo allega anche alle richieste "
        "partite da altri siti.",
        "È la base del CSRF: una pagina dell'attaccante invia una richiesta al tuo sito, il browser "
        "vi aggiunge il cookie e l'azione parte come se l'avesse chiesta la vittima.",
        "Imposta SameSite=Lax (o Strict per i cookie di sessione); usa SameSite=None solo se serve "
        "davvero, e sempre insieme a Secure."),

    # --- TLS / HTTPS ---
    "tls_obsoleto": Scheda(
        "Protocolli TLS obsoleti",
        "Il server accetta ancora versioni vecchie del protocollo ({dettaglio}), con debolezze "
        "crittografiche note.",
        "Un attaccante che intercetta il traffico forza la connessione sulla versione più debole "
        "(downgrade) e ne sfrutta le debolezze per decifrare o alterare i dati.",
        "Disabilita SSLv3, TLS 1.0 e TLS 1.1 nel server web: accetta solo TLS 1.2 e 1.3 con cifrari "
        "moderni."),
    "tls_certificato": Scheda(
        "Certificato TLS non valido",
        _significa_certificato,
        "Gli utenti si abituano ad accettare l'avviso del browser; un attaccante sulla rete presenta "
        "un proprio certificato falso e intercetta tutto il traffico (man-in-the-middle).",
        "Installa un certificato valido emesso da una CA attendibile (es. Let's Encrypt), con la "
        "catena completa e il nome host corretto."),
    "tls_scadenza": Scheda(
        "Certificato TLS in scadenza",
        "Il certificato è valido ma scade a breve.",
        "Non è una falla diretta: alla scadenza il browser blocca il sito con un avviso, e gli utenti "
        "abituati ad accettarlo diventano facili prede di certificati falsi (man-in-the-middle).",
        "Rinnova il certificato subito e automatizza il rinnovo (es. con ACME/certbot)."),
    "no_https": Scheda(
        "Sito senza HTTPS",
        "Il sito risponde su HTTP in chiaro, senza redirect verso HTTPS: niente di ciò che transita "
        "è cifrato.",
        "Chi è sulla stessa rete (Wi-Fi pubblico, provider, router compromesso) legge password e "
        "cookie di sessione e può modificare le pagine in transito.",
        "Attiva HTTPS con un certificato valido, reindirizza tutto il traffico HTTP su HTTPS e "
        "aggiungi HSTS."),

    # --- Tecnologie ---
    "tecnologia": Scheda(
        "Divulgazione di tecnologie",
        "Un header della risposta rivela il software del server ed eventualmente la versione "
        "({dettaglio}).",
        "L'attaccante usa nome e versione per cercare subito vulnerabilità ed exploit pubblici per "
        "quel software, senza dover sondare il sito.",
        "Nascondi o riduci l'header (es. server_tokens off in nginx, ServerTokens Prod in Apache, "
        "togli X-Powered-By) e tieni comunque aggiornato il software."),
    "cve": Scheda(
        "Componente con CVE note",
        "La versione dichiarata di {servizio} ha vulnerabilità note pubblicate su NVD ({cve}). La "
        "versione è letta dal solo banner: va verificato che si applichino davvero.",
        _attacco_cve,
        "Aggiorna {servizio} all'ultima versione supportata o applica le patch del fornitore; "
        "controlla su nvd.nist.gov quali CVE riguardano davvero la tua installazione."),

    # --- Analisi interna (apocalypse inspect): fonte "interno" ---
    "db_accesso": Scheda(
        "Accesso al database senza password",
        "Nel database c'è un accesso che non chiede una password ({elemento}): utente senza "
        "password, utente anonimo o regola 'trust'.",
        "Chi raggiunge il database (un'altra applicazione sulla macchina, un processo compromesso o, "
        "se la porta è aperta, chiunque in rete) entra senza credenziali e legge o modifica i dati.",
        "Assegna una password robusta a ogni utente (o usa l'autenticazione via socket per gli "
        "amministratori locali), elimina gli utenti anonimi e sostituisci 'trust' con scram-sha-256."),
    "db_privilegi": Scheda(
        "Privilegi del database troppo ampi",
        "L'utente {elemento} ha privilegi su tutto il database server (globali, SUPERUSER o "
        "simili), non solo sul database dell'applicazione.",
        "Se l'applicazione viene compromessa (es. con una SQL injection) l'attaccante eredita quei "
        "privilegi: legge tutti i database, crea utenti, con FILE o COPY ... PROGRAM legge file o "
        "esegue comandi sul server.",
        "Applica il minimo privilegio: all'utente dell'applicazione solo SELECT/INSERT/UPDATE/DELETE "
        "sul suo database; gli amministratori collegabili solo da localhost."),
    "db_configurazione": Scheda(
        "Configurazione del database",
        "Un'impostazione del database indebolisce la sicurezza: {dettaglio}.",
        "Un database raggiungibile dalla rete o senza cifratura espone credenziali e dati a chi può "
        "intercettare il traffico o tentare l'accesso direttamente alla porta.",
        "Limita l'ascolto a localhost o alla rete interna (bind-address / listen_addresses), rendi "
        "obbligatorio TLS per le connessioni di rete e disattiva le funzioni non necessarie."),
    "db_esposto": Scheda(
        "Database esposto sulla rete",
        "Il processo del database ascolta su tutte le interfacce ({elemento}): la porta è "
        "raggiungibile da qualunque macchina arrivi al server.",
        "L'attaccante prova direttamente le credenziali sulla porta del database (o sfrutta una "
        "vulnerabilità del server di database) senza passare dall'applicazione.",
        "Fai ascoltare il database solo su 127.0.0.1 (o sulla rete interna) e blocca la porta nel "
        "firewall verso l'esterno."),
    "app_root": Scheda(
        "Applicazione eseguita come root",
        "Il processo dell'applicazione ({elemento}) gira con l'utente root.",
        "Una qualunque vulnerabilità che esegue codice nell'applicazione (RCE, SSTI, "
        "deserializzazione) dà all'attaccante il controllo completo della macchina, non solo "
        "dell'applicazione.",
        "Esegui l'applicazione con un utente dedicato senza privilegi (es. www-data o un utente di "
        "servizio), con accesso in scrittura solo alle cartelle necessarie."),
    "servizio_superfluo": Scheda(
        "Servizio non necessario attivo",
        "Sulla macchina è attivo un servizio che di norma non serve a un server web ({elemento}).",
        "Ogni servizio in più è una porta d'ingresso in più: versioni vecchie, configurazioni di "
        "default o protocolli in chiaro sono bersagli facili.",
        "Disattiva e disabilita il servizio se non serve (systemctl disable --now); se serve, "
        "aggiornalo e limitane l'accesso."),
    "segreto_codice": Scheda(
        "Credenziale scritta nel codice",
        "Nel codice sorgente c'è una password o una chiave scritta in chiaro ({elemento}). Il "
        "valore non è riportato nel report.",
        "Chi ottiene il codice (repository, backup, un file esposto dal web server, un ex "
        "collaboratore) ottiene anche la credenziale e la usa per accedere ai sistemi.",
        "Sposta il segreto in una variabile d'ambiente o in un gestore di segreti, cambialo (va "
        "considerato compromesso) e toglilo anche dalla storia del repository."),
    "codice_statico": Scheda(
        "Problema rilevato dall'analisi statica",
        "L'analisi statica del codice ha trovato un costrutto rischioso ({dettaglio}).",
        "Se il costrutto riceve input dell'utente, l'attaccante può sfruttarlo: per esempio una "
        "query costruita con stringhe porta alla SQL injection, un comando di shell alla command "
        "injection.",
        "Controlla le righe indicate nel contesto: se l'input può arrivare dall'utente, correggi "
        "(query parametrizzate, niente shell, librerie sicure); altrimenti documenta perché è sicuro."),
    "file_sensibile": Scheda(
        "File sensibile accessibile",
        "Un file che può contenere segreti ({elemento}) è leggibile da tutti gli utenti della "
        "macchina o si trova dentro la cartella del codice.",
        "Un altro utente della macchina, o il web server se la cartella è servita, legge il file "
        "e ottiene password, chiavi o dati.",
        "Restringi i permessi (600 o 640, proprietario l'utente dell'applicazione) e tieni i file "
        "di configurazione e i backup fuori dalla cartella pubblicata dal web server."),
    "ws_header": Scheda(
        "Header di sicurezza non configurati nel web server",
        "La configurazione del web server non imposta alcuni header di sicurezza ({dettaglio}).",
        "Senza questi header il browser non applica protezioni aggiuntive contro XSS, clickjacking "
        "e downgrade a HTTP: un'altra vulnerabilità diventa più facile da sfruttare.",
        "Aggiungi gli header nella configurazione del web server (add_header in nginx, Header "
        "always set in Apache) oppure verifica che li imposti l'applicazione."),
    "ws_configurazione": Scheda(
        "Configurazione del web server",
        "Un'impostazione del web server dà informazioni o funzioni inutili a un attaccante "
        "({dettaglio}).",
        "L'attaccante usa le informazioni (versione, firma) per cercare exploit mirati, o il metodo "
        "TRACE per attacchi di Cross-Site Tracing.",
        "Imposta ServerSignature Off e TraceEnable Off (Apache), server_tokens off (nginx)."),
}

# Testo generico dell'attacco per categoria OWASP: per i finding di un tipo senza scheda
ATTACCO_OWASP = {
    "A01": "Un attaccante accede a dati o funzioni che il controllo degli accessi dovrebbe negargli.",
    "A02": "Un attaccante sulla rete legge o altera dati che la crittografia dovrebbe proteggere.",
    "A03": "Un attaccante invia input costruito apposta che l'applicazione esegue come codice o comando.",
    "A04": "Un attaccante sfrutta un difetto della logica dell'applicazione.",
    "A05": "Un attaccante sfrutta una configurazione lasciata debole o predefinita.",
    "A06": "Un attaccante usa vulnerabilità note del componente ed exploit pubblici.",
    "A07": "Un attaccante aggira l'autenticazione o si impossessa delle sessioni di altri utenti.",
    "A08": "Un attaccante altera software o dati di cui l'applicazione si fida senza verificarli.",
    "A09": "Un attacco in corso passa inosservato per mancanza di log e monitoraggio.",
    "A10": "Un attaccante fa eseguire al server richieste verso destinazioni scelte da lui.",
}
ATTACCO_GENERICO = "Dipende dal contesto: parti dall'evidenza riportata nel report."
FARE_GENERICO = "Valuta il finding a mano partendo dall'evidenza riportata nel report."

# Gruppi dei finding passivi, per i punti chiave
GRUPPI_PASSIVI = (
    (("header di sicurezza", "header di sicurezza"),
     ("csp", "hsts", "xfo", "xcto", "referrer", "permissions")),
    (("flag dei cookie", "flag dei cookie"), ("cookie_secure", "cookie_httponly", "cookie_samesite")),
    (("problema TLS/HTTPS", "problemi TLS/HTTPS"),
     ("tls_obsoleto", "tls_certificato", "tls_scadenza", "no_https")),
    (("tecnologia esposta", "tecnologie esposte"), ("tecnologia",)),
    (("componente con CVE note", "componenti con CVE note"), ("cve",)),
)


# ==========================================================================
# Dal finding al tipo e ai campi dei testi
# ==========================================================================

CLASSI_PENTEST = ("sqli", "xss", "cmdi", "ssti", "lfi", "redirect", "ssrf", "exposed", "csrf", "idor")

# Riconoscimento dalla voce, se la key manca: (espressione, tipo), il primo che corrisponde
_TIPI_DA_TESTO = (
    (r"\bcsrf\b|cross-site request forgery", "csrf"),
    (r"\bidor\b|insecure direct object", "idor"),
    (r"sql injection", "sqli"),
    (r"\bxss\b|cross-site scripting", "xss"),
    (r"command injection", "cmdi"),
    (r"template injection|\bssti\b", "ssti"),
    (r"path traversal|\blfi\b|file inclusion", "lfi"),
    (r"open redirect", "redirect"),
    (r"\bssrf\b|server-side request forgery", "ssrf"),
    (r"file sensibile esposto|risorsa sensibile accessibile", "exposed"),
)

_TIPI_HEADER = (
    ("divulgazione tecnologia", "tecnologia"),
    ("content-security-policy", "csp"),
    ("csp", "csp"),
    ("strict-transport-security", "hsts"),
    ("hsts", "hsts"),
    ("x-frame-options", "xfo"),
    ("x-content-type-options", "xcto"),
    ("referrer-policy", "referrer"),
    ("permissions-policy", "permissions"),
)


def classe_pentest(f):
    """La classe del finding attivo dalla key pt-<classe>-...; se la key non è nel finding
    (nel modello non c'è) la si legge dall'id, che la incorpora dopo fonte e host."""
    key = f.get("key")
    if not key:
        prefisso = f"{_slug(f.get('source'))}-{_slug(f.get('host'))}-"
        ident = f.get("id") or ""
        key = ident[len(prefisso):] if ident.startswith(prefisso) else ""
    m = re.match(r"pt-([a-z]+)-", key or "")
    return m.group(1) if m else None


def tipo_finding(f):
    """Il tipo di vulnerabilità del finding (chiave di SCHEDE), o None se nessuna regola lo
    riconosce."""
    fonte = f.get("source")
    voce = (f.get("item") or "").lower()

    if fonte == "pentest":
        classe = classe_pentest(f)
        if classe in CLASSI_PENTEST:
            return classe
    elif fonte == "header":
        for frammento, tipo in _TIPI_HEADER:
            if frammento in voce:
                return tipo
    elif fonte == "cookie":
        m = re.search(r"senza (secure|httponly|samesite)\b", voce)
        if m:
            return f"cookie_{m.group(1)}"
    elif fonte == "tls":
        if "obsolet" in voce:
            return "tls_obsoleto"
        if "scadenza" in voce:
            return "tls_scadenza"
        if "non valido" in voce:
            return "tls_certificato"
    elif fonte == "http":
        if "https" in voce:
            return "no_https"
    elif fonte in ("cve", "pacchetti"):
        if fonte == "cve" or f.get("impact") is not None:
            return "cve"
    elif fonte == "database":
        if re.search(r"senza password|anonimo|trust|password in chiaro", voce):
            return "db_accesso"
        if re.search(r"privilegi|superuser|bypassrls|root collegabile", voce):
            return "db_privilegi"
        return "db_configurazione"
    elif fonte == "servizi":
        if "database in ascolto" in voce:
            return "db_esposto"
        if "superfluo" in voce:
            return "servizio_superfluo"
    elif fonte == "processi":
        return "app_root"
    elif fonte in ("bandit", "semgrep"):
        return "segreto_codice" if "credenziale" in voce else "codice_statico"
    elif fonte == "file":
        return "file_sensibile"
    elif fonte == "webserver":
        if "versione" in voce:
            return "tecnologia"
        if "tls obsoleto" in voce:
            return "tls_obsoleto"
        if "header" in voce:
            return "ws_header"
        return "ws_configurazione"

    # ultima possibilità (anche per fonti future, es. un controllo CSRF passivo): la voce
    for espressione, tipo in _TIPI_DA_TESTO:
        if re.search(espressione, voce):
            return tipo
    return None


class _Campi(dict):
    """Segnaposto mancanti -> testo neutro, così un finding incompleto non rompe la scheda."""
    NEUTRI = {"parametro": "indicato", "cookie": "indicato", "url": "indicata",
              "dettaglio": "vedi l'evidenza", "servizio": "il componente", "cve": "vedi il report",
              "elemento": "vedi il report"}

    def __missing__(self, chiave):
        return self.NEUTRI.get(chiave, "")


def campi_finding(f):
    """I valori presi dal finding per riempire i segnaposto delle schede."""
    voce = f.get("item") or ""
    campi = _Campi()
    m = re.search(r"'([^']+)'", voce)       # "XSS riflesso su 'q'", "Cookie 'sess' senza secure"
    if f.get("source") == "pentest" and f.get("service"):
        campi["parametro"] = f"'{f['service']}'"
    elif m and f.get("source") == "pentest":
        campi["parametro"] = f"'{m.group(1)}'"
    if f.get("source") == "cookie" and m:
        campi["cookie"] = f"'{m.group(1)}'"
    if f.get("url"):
        campi["url"] = f["url"]
    # dettaglio: la parte dopo i due punti nella voce ("Protocolli TLS obsoleti accettati:
    # TLSv1, TLSv1.1") oppure la risposta osservata nell'evidenza ("server: nginx/1.10.3")
    evidenza = f.get("evidence") or ""
    if f.get("source") == "tls" and ":" in voce:
        campi["dettaglio"] = voce.split(":", 1)[1].strip()
    elif "risposta: " in evidenza:
        campi["dettaglio"] = evidenza.split("risposta: ", 1)[1].strip()
    elif evidenza:
        campi["dettaglio"] = evidenza
    if f.get("service"):
        campi["servizio"] = f["service"]
    if f.get("references"):
        campi["cve"] = elenco_cve(f["references"])
    if f.get("elemento"):
        campi["elemento"] = f["elemento"]
    return campi


# ==========================================================================
# Aiuti per i testi
# ==========================================================================

def n_(n, singolare, plurale):
    """'1 finding', '3 pagine'."""
    return f"{n} {singolare if n == 1 else plurale}"


def percento(valore):
    if valore < 0.001:
        return "meno dello 0,1%"
    return f"{valore * 100:.1f}%".replace(".", ",")


def giudizio_epss(valore):
    """Aggettivo per un EPSS, con le stesse soglie che ne ricavano la probabilità."""
    alta, moderata, bassa = (soglia for soglia, _ in EPSS_PROBABILITY)
    if valore >= alta:
        return "alta"
    if valore >= moderata:
        return "moderata"
    if valore >= bassa:
        return "bassa"
    return "molto bassa"


def elenco_cve(references, n=3):
    mostrate = ", ".join(references[:n])
    if len(references) > n:
        mostrate += f" e altre {len(references) - n}"
    return mostrate


def sigla_owasp(f):
    """'A05:2021 - Security Misconfiguration' -> 'A05' (None se il finding non ha categoria)."""
    owasp = f.get("owasp") or ""
    return owasp[:3] if re.match(r"A\d\d", owasp) else None


def nome_owasp(sigla):
    """'A05' -> 'A05 Security Misconfiguration'."""
    etichetta = OWASP.get(sigla, sigla)
    return f"{sigla} {etichetta.split(' - ', 1)[1]}" if " - " in etichetta else etichetta


def _voce(valore, f, campi):
    return valore(f, campi) if callable(valore) else valore.format_map(campi)


# ==========================================================================
# Motore
# ==========================================================================

def perche(f):
    """Perché il finding ha questo rischio: il calcolo e da dove viene la probabilità."""
    testo = (f"Impatto {f['impact']}/5 ({IMPACT_SCALE[f['impact']].lower()}) x probabilità "
             f"{f['probability']}/5 ({PROBABILITY_SCALE[f['probability']].lower()}) = "
             f"rischio {f['score']}/25, livello {f['level'].lower()}.")
    base, cve = f.get("probability_basis"), f.get("probability_cve")
    if base == "kev":
        testo += (f" {cve} è nel catalogo CISA KEV: è già sfruttata in attacchi reali, "
                  "per questo la probabilità è alta.")
    elif base == "epss" and f.get("epss") is not None:
        testo += (f" Secondo EPSS la probabilità che {cve} venga sfruttata nei prossimi 30 "
                  f"giorni è {giudizio_epss(f['epss'])} ({percento(f['epss'])}).")
    elif base == "cvss":
        testo += (f" Per {cve} non c'è un punteggio EPSS: la probabilità è stimata dal vettore "
                  "CVSS, cioè da come si sfrutta (da rete o in locale, con o senza credenziali).")
    elif f.get("source") == "pentest":
        testo += (" Il test attivo l'ha confermata con un payload: la probabilità è il valore "
                  "fisso delle regole interne per questo tipo di vulnerabilità.")
    elif f.get("references"):
        testo += (" Nessun dato KEV o EPSS per queste CVE: la probabilità è il valore fisso "
                  "delle regole interne.")
    else:
        testo += " La probabilità è il valore fisso delle regole interne per questo tipo di finding."
    return testo


def spiega(f):
    """Spiegazione di un singolo finding: tipo, le tre voci e (se valutato) il perché."""
    tipo = tipo_finding(f)
    scheda = SCHEDE.get(tipo)
    campi = campi_finding(f)
    if scheda:
        nome = scheda.nome
        significa = _voce(scheda.cosa_significa, f, campi)
        attacco = _voce(scheda.come_attaccano, f, campi)
        fare = _voce(scheda.cosa_fare, f, campi)
    else:
        sigla = sigla_owasp(f)
        nome = nome_owasp(sigla) if sigla else "Altro"
        significa = f.get("reason") or "Vedi il report completo."
        attacco = ATTACCO_OWASP.get(sigla, ATTACCO_GENERICO)
        fare = FARE_GENERICO
    valutato = f.get("impact") is not None
    return {
        "id": f.get("id"),
        "tipo": tipo,
        "nome_tipo": nome,
        "fonte": f.get("source"),
        "attivo": f.get("source") == "pentest",
        "origine": ("interno" if fonte_di(f) == "interno" else
                    "attivo" if f.get("source") == "pentest" else "passivo"),
        "esito_pt": esito_di(f),
        "owasp": sigla_owasp(f),
        "url": f.get("elemento") or f.get("url") or f.get("target"),
        "titolo": f.get("item"),
        "livello": f.get("level"),
        "score": f.get("score"),
        "kev": bool(f.get("kev")),
        "evidenza": f.get("evidence"),
        "cosa_significa": significa,
        "come_attaccano": attacco,
        "cosa_fare": fare,
        "perche": perche(f) if valutato else None,
        "urgenza": AZIONE_LIVELLO.get(f.get("level"), "") if valutato else None,
        "riferimenti": list(f.get("references") or []),
    }


def verdetto(conteggi):
    if not any(conteggi.values()):
        return "Nessuno", ("Nessun finding con rischio valutato in questa scansione. Non è una "
                           "garanzia: controlla qui sotto che cosa è stato davvero verificato.")
    if conteggi.get("Critico"):
        return "Critico", (f"Situazione critica: {n_(conteggi['Critico'], 'finding', 'finding')} "
                           "di livello critico richiedono un intervento immediato.")
    if conteggi.get("Alto"):
        return "Alto", (f"Situazione da migliorare: nessun finding critico, ma "
                        f"{conteggi['Alto']} di livello alto da correggere a breve.")
    if conteggi.get("Medio"):
        return "Medio", (f"Situazione discreta: nessun problema grave, {conteggi['Medio']} "
                         "finding di livello medio da pianificare.")
    return "Basso", (f"Situazione buona: solo {conteggi['Basso']} finding di livello basso, "
                     "miglioramenti da fare quando possibile.")


def _punti_chiave(model, scored, spiegazioni, da_verificare):
    """Le frasi di "In sintesi": come è stata fatta l'analisi e cosa ne è uscito."""
    meta = model.get("meta") or {}
    pentest = meta.get("pentest")
    punti = []

    if pentest:
        dettagli = [n_(pentest.get("pagine", 0), "pagina", "pagine"),
                    n_(pentest.get("punti_input", 0), "punto di input", "punti di input"),
                    n_(pentest.get("richieste", 0), "richiesta", "richieste")]
        if not pentest.get("crawl", True):
            dettagli.append("crawler disattivato")
        punti.append("Analisi: Vulnerability Assessment passivo + penetration testing attivo "
                     f"({', '.join(dettagli)}).")
        attive = [s for s in spiegazioni if s["attivo"]]
        if attive:
            tipi = list(dict.fromkeys(s["nome_tipo"] for s in attive))
            punti.append(f"Il test attivo ha confermato con payload "
                         f"{n_(len(attive), 'vulnerabilità', 'vulnerabilità')}: {', '.join(tipi)}.")
        else:
            punti.append("Il test attivo non ha confermato vulnerabilità sui punti di input raggiunti.")
    else:
        punti.append("Analisi: solo Vulnerability Assessment passivo (header, cookie, TLS, "
                     "tecnologie): nessun payload inviato al bersaglio.")

    conteggio_gruppi = []
    tipi_passivi = [s["tipo"] for s in spiegazioni if not s["attivo"]]
    for (singolare, plurale), tipi in GRUPPI_PASSIVI:
        n = sum(1 for t in tipi_passivi if t in tipi)
        if n:
            conteggio_gruppi.append(n_(n, singolare, plurale))
    if conteggio_gruppi:
        punti.append("Configurazione (controlli passivi): " + ", ".join(conteggio_gruppi) + ".")

    categorie = {}
    for f in scored:
        sigla = sigla_owasp(f)
        if sigla:
            categorie[sigla] = categorie.get(sigla, 0) + 1
    if categorie:
        punti.append("Categorie OWASP coinvolte: " + ", ".join(
            f"{nome_owasp(k)} ({v})" for k, v in sorted(categorie.items())) + ".")

    kev = sum(1 for f in scored if f.get("kev"))
    if kev:
        punti.append(f"{n_(kev, 'finding riguarda', 'finding riguardano')} CVE nel catalogo "
                     "CISA KEV, già sfruttate in attacchi reali.")
    if da_verificare:
        tipi = list(dict.fromkeys(s["nome_tipo"] for s in da_verificare))
        punti.append(f"{n_(len(da_verificare), 'candidato', 'candidati')} da verificare a mano: "
                     f"{', '.join(tipi)}.")
    return punti


def _limiti_interni(meta):
    """Limiti dell'analisi interna: le voci non eseguite o eseguite in parte."""
    meta_int = meta.get("interno")
    if not meta_int:
        return []
    limiti = []
    if meta_int.get("sudo") is False:
        limiti.append("Analisi interna senza sudo: processi degli altri utenti e parte della "
                      "configurazione non sono stati letti.")
    for voce, st in (meta_int.get("voci") or {}).items():
        if st.get("stato") != "eseguito":
            limiti.append(f"Analisi interna, {voce}: {st.get('stato')}"
                          + (f" ({st['dettaglio']})" if st.get("dettaglio") else "") + ".")
    return limiti


def _limiti(model, scored):
    """Che cosa questa scansione non ha controllato (l'avvertenza finale la aggiunge
    interpreta_web)."""
    meta = model.get("meta") or {}
    pentest = meta.get("pentest")
    limiti = _limiti_interni(meta)
    if not meta.get("analisi_web", True):
        return limiti      # analisi solo interna: i limiti della parte web non si applicano

    if meta.get("http_error"):
        limiti.append(f"La richiesta HTTP non è riuscita ({meta['http_error']}): header, cookie e "
                      "tecnologie non sono stati letti.")
    if meta.get("http_tls_unverified"):
        limiti.append("La pagina è stata letta senza poter verificare il certificato TLS.")
    tls = model.get("tls") or {}
    if tls.get("error"):
        limiti.append(f"Ispezione TLS non riuscita ({tls['error']}): protocolli e certificato non "
                      "sono stati verificati.")

    if pentest:
        categorie_pt = pentest.get("categorie") or {}
        if categorie_pt:
            limiti.append("Il test attivo ha provato solo: " + "; ".join(
                f"{k} {v}" for k, v in sorted(categorie_pt.items())) + ".")
        limiti.append(f"Il test attivo copre solo i "
                      f"{n_(pentest.get('punti_input', 0), 'punto di input raggiunto', 'punti di input raggiunti')}"
                      + (" dal crawler" if pentest.get("crawl", True) else
                         " (crawler disattivato: solo l'URL indicato e i suoi form)") + ".")
        if pentest.get("troncato"):
            limiti.append("La scansione attiva è stata troncata (tetto di punti o di richieste): "
                          "alcuni punti di input non sono stati provati.")
        non_testate = [k for k in sorted(OWASP) if k not in categorie_pt and k not in WEB_VA_COPERTE]
        if non_testate:
            limiti.append("Categorie OWASP non testate nemmeno dal test attivo: "
                          + ", ".join(nome_owasp(k) for k in non_testate) + ".")
    else:
        limiti.append("Penetration testing attivo non eseguito (opzione --pentest): non sono state "
                      "cercate vulnerabilità che richiedono payload. Non testate: " + "; ".join(
                          f"{k} {v}" for k, v in sorted(WEB_VA_FUORI_PORTATA.items())) + ".")

    rilevate = model.get("tecnologie_rilevate") or []
    disattivata = [t for t in rilevate if "--no-nvd" in (t.get("cve_errore") or "")]
    fallite = [t for t in rilevate if t.get("cve_errore") and t not in disattivata]
    senza_versione = [t for t in rilevate
                      if not t.get("versione") and (t.get("prodotto") or "").lower() in WEB_TECH_CPE]

    def nomi(elenco):
        return ", ".join(f"{t.get('prodotto')} {t.get('versione') or ''}".strip() for t in elenco)

    if disattivata:
        limiti.append(f"Ricerca CVE su NVD disattivata (--no-nvd): CVE non cercate per {nomi(disattivata)}.")
    if fallite:
        limiti.append(f"Ricerca CVE su NVD non riuscita per {nomi(fallite)}.")
    if senza_versione:
        limiti.append(f"Versione non dichiarata per {nomi(senza_versione)}: le CVE non sono "
                      "determinabili in modo passivo.")
    if meta.get("threat_intel") is None and any(f.get("source") == "cve" for f in scored):
        limiti.append("Dati KEV/EPSS non disponibili: la probabilità delle CVE è stimata da CVSS "
                      "o da valori fissi.")
    return limiti


def interpreta_web(model, max_priorita=MAX_PRIORITA):
    """Lettura guidata del modello del report web (web_report.build_web_model)."""
    meta = model.get("meta") or {}
    findings = model.get("findings") or []
    scored = sorted((f for f in findings if f.get("impact") is not None),
                    key=lambda f: (f.get("score") or 0, f.get("impact") or 0), reverse=True)
    conteggi = {lv: sum(1 for f in scored if f.get("level") == lv) for lv in LIVELLI}
    livello, testo = verdetto(conteggi)
    spiegazioni = [spiega(f) for f in scored]
    # gli indizi del test attivo senza rischio valutato (es. SSRF candidata): da verificare a
    # mano. Gli altri informativi (es. "ricerca CVE non eseguita") finiscono nei limiti.
    da_verificare = [s for s in (spiega(f) for f in findings
                                 if f.get("impact") is None and f.get("source") == "pentest")
                     if s["tipo"] in SCHEDE]
    autorizzazione = meta.get("autorizzazione") or {}
    return {
        "meta": {
            "target": meta.get("target"),
            "generated_at": meta.get("generated_at"),
            "mode": meta.get("mode"),
            "ambiente": autorizzazione.get("ambiente"),
            "pentest": bool(meta.get("pentest")),
        },
        "verdetto": {"livello": livello, "testo": testo},
        "conteggi": conteggi,
        "punti_chiave": _punti_chiave(model, scored, spiegazioni, da_verificare),
        "priorita": spiegazioni[:max_priorita],
        "spiegazioni": spiegazioni,
        "da_verificare": da_verificare,
        "limiti": _limiti(model, scored) + [AVVERTENZA_FINALE],
    }


# ==========================================================================
# Markdown
# ==========================================================================

def _codice(testo):
    """Testo in un blocco di codice inline: niente interpretazione Markdown di payload e URL."""
    testo = str(testo).replace("\n", " ")
    return f"`` {testo} ``" if "`" in testo else f"`{testo}`"


def _scheda_md(s):
    return [
        f"**Cosa significa.** {s['cosa_significa']}\n",
        f"**Come viene attaccata.** {s['come_attaccano']}\n",
        f"**Cosa fare.** {s['cosa_fare']}\n",
    ]


def _sottotitolo(s):
    parti = [f"{s['livello']} ({s['score']})" if s["perche"] else s["livello"]]
    if s["kev"]:
        parti.append("KEV")
    parti.append(s["nome_tipo"])
    if s["owasp"]:
        parti.append(nome_owasp(s["owasp"]))
    parti.append(s.get("origine") or ("attivo" if s["attivo"] else "passivo"))
    if s.get("esito_pt"):
        parti.append(f"Esito PT: {s['esito_pt']}")
    return " · ".join(parti)


def render_markdown(lettura):
    meta = lettura["meta"]
    data = (meta.get("generated_at") or "-").replace("T", " ")
    righe = [
        "# Interpretazione del report web\n",
        f"**Target:** {meta.get('target') or '-'}  ",
        f"**Report del:** {data}  ",
        f"**Analisi:** {meta.get('mode') or '-'}  ",
    ]
    if meta.get("ambiente"):
        righe.append(f"**Ambiente:** {meta['ambiente']}  ")
    righe += [
        "",
        "> Lettura guidata generata da regole fisse a partire dai dati del report: per ogni "
        "finding spiega cosa significa, come viene attaccato e cosa fare. Tutti i dettagli "
        "tecnici sono nel report completo.\n",
        "## In sintesi\n",
        f"**{lettura['verdetto']['testo']}**\n",
        "| " + " | ".join(LIVELLI) + " |",
        "|" + "---:|" * len(LIVELLI),
        "| " + " | ".join(str(lettura["conteggi"][lv]) for lv in LIVELLI) + " |\n",
    ]
    righe += [f"- {p}" for p in lettura["punti_chiave"]]
    if lettura["punti_chiave"]:
        righe.append("")

    if lettura["priorita"]:
        righe.append("## Da dove cominciare\n")
        righe.append(f"I {len(lettura['priorita'])} finding con il rischio più alto, in ordine.\n")
        for n, s in enumerate(lettura["priorita"], start=1):
            righe.append(f"### {n}. {s['titolo']}\n")
            righe.append(f"*{_sottotitolo(s)}* · {_codice(s['url'])}\n")
            righe += _scheda_md(s)
            righe.append(f"**Perché questo livello.** {s['perche']} {s['urgenza']}\n")
            if s["evidenza"]:
                righe.append(f"**Evidenza.** {_codice(s['evidenza'])}\n")

    altri = lettura["spiegazioni"][len(lettura["priorita"]):]
    if altri:
        righe.append("## Tutti gli altri finding, per categoria OWASP\n")
        sigle = sorted({s["owasp"] for s in altri if s["owasp"]}) + [None]
        for sigla in sigle:
            gruppo = [s for s in altri if s["owasp"] == sigla]
            if not gruppo:
                continue
            righe.append(f"### {nome_owasp(sigla) if sigla else 'Senza categoria OWASP'}\n")
            for s in gruppo:
                righe.append(f"- **{s['livello']} ({s['score']})** {s['titolo']} · {s['nome_tipo']}  ")
                righe.append(f"  *Cosa significa:* {s['cosa_significa']}  ")
                righe.append(f"  *Come viene attaccata:* {s['come_attaccano']}  ")
                righe.append(f"  *Cosa fare:* {s['cosa_fare']}")
            righe.append("")

    if lettura["da_verificare"]:
        righe.append("## Da verificare a mano\n")
        righe.append("Indizi senza un rischio valutato: la scansione non li ha potuti confermare.\n")
        for s in lettura["da_verificare"]:
            righe.append(f"### {s['titolo']}\n")
            righe.append(f"*{_sottotitolo(s)}* · {_codice(s['url'])}\n")
            righe += _scheda_md(s)

    righe.append("## Cosa questa lettura non copre\n")
    righe += [f"- {lim}" for lim in lettura["limiti"]]
    return "\n".join(righe) + "\n"


def percorso_interpretazione(nome_report):
    """reports/md/<nome-report>_interpretazione.md (stessa regola di --output dei report)."""
    return percorso_output(nome_report, "md", SUFFISSO_INTERPRETAZIONE)


def salva(lettura, nome_report):
    """Scrive la lettura in Markdown accanto ai report e ne restituisce il percorso."""
    return scrivi(percorso_interpretazione(nome_report), render_markdown(lettura))


# ==========================================================================
# Terminale (colori di menu_stile: palette fucsia di ApocalypseStriker)
# ==========================================================================

def print_interpretazione(lettura, percorso=None, larghezza=st.LARGHEZZA):
    """Stampa a terminale verdetto, punti chiave e priorità con le tre voci; il resto
    (tutti i finding, i limiti completi) è nel file."""
    c = st.c

    def a_capo(testo, rientro, colore="", seguito=None):
        # niente a capo sui trattini: spezzerebbe opzioni e header (--pentest, x-frame-options)
        for r in textwrap.wrap(testo, larghezza, initial_indent=rientro,
                               subsequent_indent=seguito or rientro, break_on_hyphens=False):
            spazi = len(r) - len(r.lstrip(" "))
            print(r[:spazi] + c(r[spazi:], colore))

    titolo = " COSA SIGNIFICA "
    lato = (larghezza - len(titolo)) // 2
    print()
    print(c("=" * lato, st.CORNICE) + c(titolo, st.TITOLO)
          + c("=" * (larghezza - lato - len(titolo)), st.CORNICE))
    print()
    livello = lettura["verdetto"]["livello"]
    a_capo(lettura["verdetto"]["testo"], "  ", st.COLORE_RISCHIO.get(livello, st.GRASSETTO))
    for p in lettura["punti_chiave"]:
        a_capo(f"- {p}", "    ", seguito="      ")
    print()

    if lettura["priorita"]:
        print(c("  Da dove cominciare", st.TITOLO))
        print(c("-" * larghezza, st.CORNICE))
        for n, s in enumerate(lettura["priorita"], start=1):
            colore = st.COLORE_RISCHIO.get(s["livello"], st.GRASSETTO)
            kev = c(" KEV", st.AVVISO) if s["kev"] else ""
            intestazione = f"{n}. {s['livello']} ({s['score']})"
            print(f"  {c(intestazione, colore)}{kev}  {c(s['titolo'], st.GRASSETTO)}")
            a_capo(s["url"] or "", "     ", st.GRIGIO)
            a_capo(f"Cosa significa: {s['cosa_significa']}", "     ", seguito="       ")
            a_capo(f"Come viene attaccata: {s['come_attaccano']}", "     ", seguito="       ")
            a_capo(f"> Cosa fare: {s['cosa_fare']}", "     ", st.AZIONE, seguito="       ")
            print()

    if lettura["da_verificare"]:
        print(c(f"  Da verificare a mano: {len(lettura['da_verificare'])} (dettagli nel file)", st.TITOLO))
        print()
    limiti = lettura["limiti"][:-1]   # l'ultimo è l'avvertenza generale, che resta nel file
    if limiti:
        print(c("  Cosa non è stato controllato", st.TITOLO))
        for lim in limiti:
            a_capo(f"- {lim}", "    ", st.GRIGIO, seguito="      ")
        print()
    if percorso:
        print(f"  {c('Lettura completa, con tutti i finding:', st.GRIGIO)}  {percorso}")
    print(c("=" * larghezza, st.CORNICE))
