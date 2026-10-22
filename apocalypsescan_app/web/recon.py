"""recon.py - Ricognizione passiva di un'applicazione web (sola lettura).

Legge quello che il server dichiara da sé a una normale richiesta HTTP(S): header di
risposta, cookie, versione TLS e certificato, tecnologie esposte nei banner. NON invia
payload né sollecita il bersaglio: è l'equivalente di aprire il sito con un browser e
guardare gli header. Nessun punteggio di rischio qui: questo modulo raccoglie e basta;
la valutazione (impatto x probabilità, categoria OWASP) spetta a web_risk.py.

La forma dei dizionari restituiti ricalca l'output reale osservato su badssl.com:
headers case-insensitive, Set-Cookie come lista, ssl.getpeercert() per il certificato.
"""
import re
import socket
import ssl
import warnings
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from ..config import WEB_DISTRO_MARKERS

# Header di sicurezza che ci aspettiamo da un'app moderna. La chiave è in minuscolo
# perché il confronto è case-insensitive; il valore è una descrizione breve a cosa serve.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS: forza il browser a usare sempre HTTPS",
    "content-security-policy": "CSP: limita le sorgenti di script e risorse (anti-XSS)",
    "x-content-type-options": "Impedisce il MIME sniffing (atteso: nosniff)",
    "x-frame-options": "Anti-clickjacking (o equivalente CSP frame-ancestors)",
    "referrer-policy": "Controlla quante informazioni di provenienza vengono inviate",
    "permissions-policy": "Limita l'accesso a funzionalità del browser (camera, geoloc...)",
}

# Header che, se presenti, rivelano tecnologia/versione: utili al difensore, ma anche
# informazione in più per un attaccante (fingerprinting).
TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-runtime", "x-drupal-cache", "via")

# Cookie di sessione che rivelano la piattaforma (senza versione). Chiave: prefisso del nome,
# in minuscolo (ASP classico aggiunge lettere casuali: ASPSESSIONIDCAASTDSA su testasp.vulnweb.com)
COOKIE_TECNOLOGIA = {"phpsessid": "PHP", "jsessionid": "Java (servlet)",
                     "asp.net_sessionid": "ASP.NET", "aspsessionid": "ASP classico",
                     "laravel_session": "Laravel", "connect.sid": "Express (Node.js)",
                     "ci_session": "CodeIgniter"}

# "prodotto/versione" nei banner: nginx/1.10.3, Microsoft-IIS/8.5, OpenSSL/1.0.1f, PHP/5.6.40-38+ubuntu...
_PRODOTTO_VERSIONE = re.compile(r"([A-Za-z][\w.+-]*?)/v?(\d+(?:\.\d+)+[a-z]?)")
# "Prodotto versione" nel meta generator: "WordPress 6.4.2", "Drupal 10 (https://...)"
_GENERATOR = re.compile(r"^\s*([A-Za-z][\w .-]*?)\s+v?(\d+(?:\.\d+)*)")
_META_GENERATOR = (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I),
                   re.compile(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator", re.I))
# Header che rivelano il prodotto con il loro NOME, non con il valore (x-drupal-cache: HIT,
# x-runtime: 0.012): il valore non va letto come nome di prodotto
HEADER_PRODOTTO = {"x-drupal-cache": "Drupal", "x-runtime": "Ruby on Rails"}
LIMITE_CORPO = 256 * 1024     # del corpo si legge solo l'inizio, dove sta il meta generator

UA = "ApocalypseStriker-recon/0.1 (solo lettura)"
TIMEOUT = 15
# Un timeout isolato non è un dato sul bersaglio (osservato su badssl.com): si ritenta.
# I rifiuti veri (alert TLS, reset, 4xx/5xx) non vengono mai ritentati.
RIPROVE_TIMEOUT = 1

# Versioni TLS provate una alla volta, dalla più vecchia alla più recente. Il contesto di
# default di Python rifiuta da sé TLS 1.0/1.1: senza una prova per versione il server che
# offre solo protocolli vecchi sembrerebbe avere un certificato rotto.
VERSIONI_TLS = (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3))
# OpenSSL 3 (quello di Python) non implementa più SSLv2/SSLv3: non sono verificabili da qui,
# quindi vanno dichiarati come "non verificati", non come assenti.
NON_VERIFICABILI = ("SSLv2", "SSLv3")


def normalizza_url(url):
    """Aggiunge https:// se manca lo schema e scarta frammenti. Ritorna (url, parsed)."""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"URL senza host: {url!r}")
    pulito = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
    return pulito, urlparse(pulito)


def _riprova(funzione, *args, **kwargs):
    """Esegue funzione(*args, **kwargs) ritentando, fino a RIPROVE_TIMEOUT volte, solo se
    scade il timeout (anche quando urllib lo incapsula in un URLError)."""
    for tentativo in range(RIPROVE_TIMEOUT + 1):
        ultimo = tentativo == RIPROVE_TIMEOUT
        try:
            return funzione(*args, **kwargs)
        except TimeoutError:
            if ultimo:
                raise
        except URLError as e:
            if ultimo or not isinstance(e.reason, TimeoutError):
                raise


def _contesto_permissivo(versione=None):
    """Contesto TLS che accetta protocolli vecchi e certificati non validi. Serve a VEDERE
    cosa offre il server, non a fidarsi della connessione. Con 'versione' l'handshake è
    limitato a quella sola versione."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)   # TLSv1/1.1 deprecati nel modulo ssl
        ctx.minimum_version = versione or ssl.TLSVersion.TLSv1
        if versione is not None:
            ctx.maximum_version = versione
    if versione is None or versione < ssl.TLSVersion.TLSv1_2:
        # i cifrari dei protocolli vecchi stanno sotto il livello di sicurezza di default
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def leggi_http(url):
    """Esegue una GET e restituisce status, URL finale (dopo i redirect), header e cookie.
    Gli errori HTTP (4xx/5xx) non sono eccezioni: il server ha risposto, quindi i suoi
    header vanno letti comunque. Solo gli errori di rete danno {'error': ...}.

    Se il client rifiuta il TLS (certificato non valido, protocollo vecchio) la GET viene
    ripetuta senza verifica: il difetto TLS lo registra ispeziona_tls(), qui conta non
    perdere header e cookie. 'verifica_tls_fallita' riporta l'errore della prima lettura."""
    req = Request(url, method="GET", headers={"User-Agent": UA})
    verifica_fallita = None
    try:
        risposta = _riprova(urlopen, req, timeout=TIMEOUT)
    except HTTPError as e:
        risposta = e                      # 4xx/5xx: ha comunque header e corpo
    except URLError as e:
        if not isinstance(e.reason, ssl.SSLError):
            return {"error": f"{type(e).__name__}: {e}"}
        verifica_fallita = f"{type(e.reason).__name__}: {e.reason}"
        try:
            risposta = _riprova(urlopen, req, timeout=TIMEOUT, context=_contesto_permissivo())
        except HTTPError as e2:
            risposta = e2
        except (URLError, OSError) as e2:
            return {"error": f"{type(e2).__name__}: {e2}", "verifica_tls_fallita": verifica_fallita}
    except (socket.timeout, ssl.SSLError, OSError) as e:
        return {"error": f"{type(e).__name__}: {e}"}

    with risposta:
        # http.client.HTTPMessage: accesso case-insensitive, con get_all per i doppioni
        headers = {k.lower(): v for k, v in risposta.headers.items()}
        set_cookie = risposta.headers.get_all("Set-Cookie") or []
        finale = risposta.url
        try:
            corpo = risposta.read(LIMITE_CORPO).decode("utf-8", errors="replace")
        except OSError:
            corpo = ""
        return {
            "status": risposta.status,
            "final_url": finale,
            "redirected": finale != url,
            "upgraded_https": url.startswith("http://") and finale.startswith("https://"),
            "verifica_tls_fallita": verifica_fallita,
            "headers": headers,
            "cookies": [_analizza_cookie(c) for c in set_cookie],
            "generator": _meta_generator(corpo),
        }


def _meta_generator(corpo):
    """Contenuto di <meta name="generator"> della pagina, se presente (in qualunque ordine di attributi)."""
    for regex in _META_GENERATOR:
        trovato = regex.search(corpo)
        if trovato:
            return trovato.group(1).strip()
    return None


def _set_cookie_oscurato(raw):
    """La riga Set-Cookie così come l'ha inviata il server, ma con il valore del cookie
    sostituito: è spesso un token di sessione e non deve finire in un report."""
    coppia, sep, attributi = raw.partition(";")
    return f"{coppia.split('=', 1)[0].strip()}=<valore omesso>{sep}{attributi}"


def _analizza_cookie(raw):
    """Estrae nome e flag di sicurezza da una riga Set-Cookie; 'set_cookie' è la riga
    originale con il valore oscurato (evidenza per il report)."""
    oscurato = _set_cookie_oscurato(raw)
    sc = SimpleCookie()
    try:
        sc.load(raw)
        nome, morsel = next(iter(sc.items()))
    except Exception:
        return {"set_cookie": oscurato, "parse_error": True}
    return {
        "name": nome,
        "secure": bool(morsel["secure"]),
        "httponly": bool(morsel["httponly"]),
        "samesite": morsel["samesite"] or None,
        "set_cookie": oscurato,
    }


def analizza_hsts(valore):
    """Scompone Strict-Transport-Security. Le direttive sono case-insensitive (su
    hsts.badssl.com si legge 'includeSubdomains'). max_age None = assente o non numerico."""
    direttive = {}
    for parte in valore.split(";"):
        nome, _, arg = parte.strip().partition("=")
        if nome:
            direttive[nome.strip().lower()] = arg.strip().strip('"')
    max_age = direttive.get("max-age")
    return {
        "max_age": int(max_age) if max_age and max_age.isdigit() else None,
        "include_subdomains": "includesubdomains" in direttive,
        "preload": "preload" in direttive,
    }


def analizza_csp(valore):
    """Scompone una Content-Security-Policy in {direttiva: [sorgenti]}, tutto in minuscolo.
    Se una direttiva è ripetuta vale la prima, come nei browser."""
    politica = {}
    for parte in valore.split(";"):
        token = parte.split()
        if token and token[0].lower() not in politica:
            politica[token[0].lower()] = [t.lower() for t in token[1:]]
    return politica


def classifica_header(headers):
    """Divide gli header noti in: di sicurezza presenti, di sicurezza mancanti, tecnologici.
    Non assegna punteggi: dice cosa c'è, cosa manca e com'è scritto (HSTS e CSP scomposti)."""
    presenti = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    mancanti = {h: desc for h, desc in SECURITY_HEADERS.items() if h not in headers}
    tecnologie = {h: headers[h] for h in TECH_HEADERS if h in headers}
    dettaglio = {}
    if "strict-transport-security" in headers:
        dettaglio["hsts"] = analizza_hsts(headers["strict-transport-security"])
    if "content-security-policy" in headers:
        dettaglio["csp"] = analizza_csp(headers["content-security-policy"])
    # la versione Report-Only segnala soltanto, non blocca nulla: la si registra a parte
    if "content-security-policy-report-only" in headers:
        dettaglio["csp_report_only"] = analizza_csp(headers["content-security-policy-report-only"])
    return {"security_presenti": presenti, "security_mancanti": mancanti,
            "tecnologie": tecnologie, "dettaglio": dettaglio}


def _prova_versione(host, port, versione):
    """Un handshake limitato a una sola versione TLS. Ritorna il cifrario negoziato se il
    server la accetta, None se la rifiuta. Gli errori di rete (host irraggiungibile,
    timeout) salgono al chiamante: non dicono nulla sulla versione."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with _contesto_permissivo(versione).wrap_socket(sock, server_hostname=host) as ss:
                return ss.cipher()[0]
    except (ssl.SSLError, ConnectionResetError):
        # alert di handshake, o connessione chiusa dal server (così risponde Windows): rifiutata
        return None


def _verifica_certificato(host, port, versione):
    """Validazione del certificato come la farebbe un browser (CA attendibile, hostname,
    scadenza), ma sulla versione TLS che il server accetta davvero: così un protocollo
    vecchio non viene scambiato per un certificato rotto."""
    ctx = ssl.create_default_context()
    if versione < ssl.TLSVersion.TLSv1_2:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = versione
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    def handshake():
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert()

    try:
        cert = _riprova(handshake)
    except ssl.SSLCertVerificationError as e:
        # il certificato c'è ma non è attendibile → dato rilevante, non un errore da nascondere
        return {"cert_valido": False, "cert_error": f"{type(e).__name__}: {e}"}
    except (ssl.SSLError, OSError) as e:
        return {"cert_valido": None, "cert_error": f"{type(e).__name__}: {e}"}
    return {
        "cert_valido": True,
        "cert_subject": _nome_cert(cert.get("subject")),
        "cert_issuer": _nome_cert(cert.get("issuer")),
        "not_after": cert.get("notAfter"),
        "giorni_a_scadenza": _giorni_a_scadenza(cert.get("notAfter")),
    }


def rileva_tecnologie(http):
    """Tecnologie che l'app dichiara da sé: banner negli header, meta generator, nomi dei
    cookie di sessione. Ogni voce: prodotto, versione (None se non dichiarata), fonte,
    evidenza (il testo letto) e distro (marcatore di distribuzione nel banner, o None).
    Nessun giudizio: cosa farne lo decidono cve_nvd.py e web_risk.py."""
    trovate = []
    headers = http.get("headers", {})
    for header in TECH_HEADERS:
        valore = headers.get(header)
        if not valore or header == "via":      # 'via' elenca i proxy, non l'applicazione
            continue
        minuscolo = valore.lower()
        distro = next((m for m in WEB_DISTRO_MARKERS if m in minuscolo), None)
        coppie = _PRODOTTO_VERSIONE.findall(valore)
        if header in HEADER_PRODOTTO:
            coppie = [(HEADER_PRODOTTO[header], None)]
        elif header == "x-aspnet-version":
            coppie = [("ASP.NET", valore.strip())]
        elif header == "x-generator" and _GENERATOR.match(valore):
            coppie = [tuple(g.strip() for g in _GENERATOR.match(valore).groups())]
        elif not coppie:
            coppie = [(valore.split()[0], None)]   # "Apache", "nginx", "ASP.NET": solo il nome
        for prodotto, versione in coppie:
            trovate.append({"prodotto": prodotto, "versione": versione, "fonte": f"header {header}",
                            "evidenza": f"{header}: {valore}", "distro": distro})

    generator = http.get("generator")
    if generator:
        trovato = _GENERATOR.match(generator)
        prodotto, versione = (trovato.group(1).strip(), trovato.group(2)) if trovato else (generator, None)
        trovate.append({"prodotto": prodotto, "versione": versione, "fonte": "meta generator",
                        "evidenza": f'<meta name="generator" content="{generator}">', "distro": None})

    for cookie in http.get("cookies", []):
        nome = (cookie.get("name") or "").lower()
        prodotto = next((p for prefisso, p in COOKIE_TECNOLOGIA.items() if nome.startswith(prefisso)), None)
        if prodotto:
            trovate.append({"prodotto": prodotto, "versione": None, "fonte": f"cookie {cookie['name']}",
                            "evidenza": f"Set-Cookie: {cookie['name']}=...", "distro": None})

    # stesso prodotto e versione da più fonti: si tiene la prima (gli header vengono prima);
    # un prodotto senza versione si scarta se un'altra fonte ne dichiara la versione
    unici = {}
    for t in trovate:
        unici.setdefault((t["prodotto"].lower(), t["versione"]), t)
    con_versione = {p for p, v in unici if v}
    return [t for (p, v), t in unici.items() if v or p not in con_versione]


def ispeziona_tls(host, port=443):
    """Ispezione TLS in sola lettura: quali versioni il server accetta (un handshake per
    versione, nessun payload), la migliore con il suo cifrario, e la validità del
    certificato. 'error' solo se il server non è raggiungibile o non parla TLS."""
    endpoint = f"{host}:{port}"
    protocolli = {}
    try:
        for nome, versione in VERSIONI_TLS:
            protocolli[nome] = _riprova(_prova_versione, host, port, versione)
    except OSError as e:
        return {"endpoint": endpoint, "error": f"{type(e).__name__}: {e}", "handshake_fallito": False}

    accettati = [nome for nome, cifrario in protocolli.items() if cifrario]
    if not accettati:
        return {"endpoint": endpoint, "error": "Nessuna versione TLS accettata (provate TLS 1.0-1.3)",
                "handshake_fallito": True, "protocolli": {n: False for n in protocolli}}

    migliore = accettati[-1]
    risultato = {
        "endpoint": endpoint,
        "protocol": migliore,
        "cipher": protocolli[migliore],
        "protocolli": {nome: bool(cifrario) for nome, cifrario in protocolli.items()},
        "non_verificati": list(NON_VERIFICABILI),
    }
    risultato.update(_verifica_certificato(host, port, dict(VERSIONI_TLS)[migliore]))
    return risultato


def _nome_cert(campi):
    """subject/issuer di getpeercert() è una tupla di tuple: la appiattisce in dict."""
    if not campi:
        return {}
    return {k: v for parte in campi for (k, v) in parte}


def _giorni_a_scadenza(not_after):
    """Giorni mancanti alla scadenza del certificato (negativo = già scaduto)."""
    if not not_after:
        return None
    try:
        scadenza = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (scadenza - datetime.now(timezone.utc)).days


def recon(url):
    """Ricognizione completa di un URL: HTTP + classificazione header + TLS (se https).
    Restituisce un dizionario grezzo pronto per web_risk.py. Non solleva eccezioni sui
    problemi del bersaglio: li registra nei rispettivi campi 'error'."""
    url, parsed = normalizza_url(url)
    http = leggi_http(url)

    risultato = {"target": url, "host": parsed.hostname, "http": http}
    if "headers" in http:
        risultato["classi"] = classifica_header(http["headers"])
        risultato["tecnologie_rilevate"] = rileva_tecnologie(http)
    # il TLS si ispeziona sull'URL finale: se http:// è stato promosso a https://, conta quello
    schema_finale = urlparse(http.get("final_url", url)).scheme
    if schema_finale == "https":
        porta = parsed.port or 443
        risultato["tls"] = ispeziona_tls(parsed.hostname, porta)
    return risultato


if __name__ == "__main__":
    import json
    import sys
    bersaglio = sys.argv[1] if len(sys.argv) > 1 else "https://badssl.com"
    print(json.dumps(recon(bersaglio), indent=2, ensure_ascii=False, default=str))
