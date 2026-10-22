"""web_risk.py - Valutazione dei risultati della ricognizione web.

Trasforma l'output grezzo di recon.recon() in una lista di finding già pesati
(impatto x probabilità, come in risk.py), ciascuno con la sua categoria OWASP, l'URL
e un'evidenza sintetica. È l'analogo web di assess_host_risks()/parse_trivy(): la
raccolta sta in recon.py, qui c'è solo il giudizio. I valori di impatto/probabilità
vengono da config.py (blocco VAPT web), non sono scritti qui.
"""
from ..config import (
    OWASP, WEB_MISSING_HEADER, WEB_COOKIE_FLAG, WEB_TECH_DISCLOSURE,
    WEB_TLS_WEAK_PROTOCOLS, WEB_TLS_OLD, WEB_TLS_CERT_INVALID,
    WEB_TLS_CERT_EXPIRING_DAYS, WEB_TLS_CERT_EXPIRING,
    WEB_HSTS_MIN_MAX_AGE, WEB_HSTS_SHORT, WEB_HSTS_DISABLED,
    WEB_CSP_WILDCARD_SOURCES, WEB_CSP_WEAK, WEB_CSP_NO_SCRIPT_RULE,
    WEB_XCTO_WEAK, WEB_XFO_WEAK, WEB_REFERRER_WEAK,
    WEB_CVE_IMPACT, WEB_CVE_DEFAULT_IMPACT, WEB_CVE_PROBABILITY, WEB_CVE_MAX_PROBABILITY,
    WEB_CVE_BACKPORT_MAX_PROBABILITY, WEB_TECH_CPE, WEB_NO_HTTPS,
)
from ..risk import info_finding, make_finding, sort_findings
from ..threat_intel import assess_cves


def _finding(source, item, regola, url, evidence):
    """Crea un finding web da una regola (owasp, impatto, probabilità, motivazione)."""
    owasp_key, impatto, prob, motivo = regola
    return make_finding(source, item, impatto, prob, motivo,
                        owasp=OWASP[owasp_key], url=url, evidence=evidence)


def _richiesta(recon_result):
    """La richiesta che ha prodotto la risposta osservata: metodo, URL, esito, eventuale
    redirect. È la parte "richiesta" dell'evidenza di ogni finding HTTP."""
    http = recon_result.get("http", {})
    testo = f"GET {recon_result.get('target')} → "
    if "error" in http:
        return testo + f"nessuna risposta ({http['error']})"
    testo += str(http.get("status"))
    if http.get("redirected"):
        testo += f" dopo redirect a {http.get('final_url')}"
    if http.get("verifica_tls_fallita"):
        testo += " (TLS non verificato)"
    return testo


def _is_https(recon_result):
    """True se l'URL finale (dopo i redirect) è su HTTPS."""
    finale = recon_result.get("http", {}).get("final_url", recon_result.get("target", ""))
    return str(finale).startswith("https://")


def _valuta_header(classi, url, https):
    """Finding per gli header di sicurezza mancanti."""
    findings = []
    dettaglio = classi.get("dettaglio", {})
    for header in classi.get("security_mancanti", {}):
        # HSTS su un sito HTTP è inutile: il browser lo ignorerebbe comunque
        if header == "strict-transport-security" and not https:
            continue
        # frame-ancestors della CSP sostituisce X-Frame-Options (e ha la precedenza)
        if header == "x-frame-options" and "frame-ancestors" in dettaglio.get("csp", {}):
            continue
        regola = WEB_MISSING_HEADER.get(header)
        if regola:
            evidenza = f"{header}: (assente)"
            if header == "content-security-policy" and "csp_report_only" in dettaglio:
                evidenza += "; presente solo content-security-policy-report-only (segnala, non blocca)"
            findings.append(_finding("header", f"Header mancante: {header}", regola,
                                     url=url, evidence=evidenza))
    return findings


def _problemi_csp(politica):
    """(direttiva valutata, sorgenti permissive) per gli script di una CSP; direttiva None
    se la politica non limita affatto gli script. Applica le regole CSP3 di config.py."""
    direttiva = next((d for d in ("script-src", "default-src") if d in politica), None)
    if direttiva is None:
        return None, []
    sorgenti = politica[direttiva]
    nonce_o_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sorgenti)
    strict_dynamic = "'strict-dynamic'" in sorgenti
    problemi = []
    if "'unsafe-inline'" in sorgenti and not nonce_o_hash:
        problemi.append("'unsafe-inline'")
    if "'unsafe-eval'" in sorgenti:
        problemi.append("'unsafe-eval'")
    if not strict_dynamic:
        problemi += [s for s in sorgenti if s in WEB_CSP_WILDCARD_SOURCES]
    return direttiva, problemi


def _valuta_header_deboli(classi, url, https):
    """Finding per gli header di sicurezza presenti ma scritti in modo da non proteggere."""
    findings = []
    presenti = classi.get("security_presenti", {})
    dettaglio = classi.get("dettaglio", {})

    hsts = dettaglio.get("hsts")
    if hsts and https:
        valore = presenti["strict-transport-security"]
        if not hsts["max_age"]:          # None (assente/illeggibile) oppure 0
            findings.append(_finding("header", "HSTS inefficace (max-age assente o 0)", WEB_HSTS_DISABLED,
                                     url=url, evidence=f"strict-transport-security: {valore}"))
        elif hsts["max_age"] < WEB_HSTS_MIN_MAX_AGE:
            giorni = hsts["max_age"] // 86400
            durata = f"{giorni} giorni" if giorni else f"{hsts['max_age']} secondi"
            findings.append(_finding("header", f"HSTS con max-age breve ({durata})", WEB_HSTS_SHORT,
                                     url=url, evidence=f"strict-transport-security: {valore} "
                                                       f"(max-age minimo atteso {WEB_HSTS_MIN_MAX_AGE})"))

    csp = dettaglio.get("csp")
    if csp is not None:
        direttiva, problemi = _problemi_csp(csp)
        if direttiva is None:
            findings.append(_finding("header", "CSP senza regole per gli script", WEB_CSP_NO_SCRIPT_RULE,
                                     url=url, evidence="content-security-policy: (né script-src né default-src)"))
        elif problemi:
            # della CSP (anche molto lunga) si riporta solo la direttiva che conta
            findings.append(_finding("header", f"CSP permissiva: {', '.join(problemi)}", WEB_CSP_WEAK,
                                     url=url, evidence=f"content-security-policy: … {direttiva} "
                                                       f"{' '.join(csp[direttiva])} …"))

    xcto = presenti.get("x-content-type-options")
    if xcto is not None and xcto.strip().lower() != "nosniff":
        findings.append(_finding("header", "X-Content-Type-Options non valido", WEB_XCTO_WEAK,
                                 url=url, evidence=f"x-content-type-options: {xcto}"))

    xfo = presenti.get("x-frame-options")
    if (xfo is not None and xfo.strip().lower() not in ("deny", "sameorigin")
            and "frame-ancestors" not in (csp or {})):
        findings.append(_finding("header", "X-Frame-Options non valido", WEB_XFO_WEAK,
                                 url=url, evidence=f"x-frame-options: {xfo}"))

    referrer = presenti.get("referrer-policy")
    # con più valori separati da virgola il browser applica l'ultimo che riconosce
    if referrer is not None and referrer.split(",")[-1].strip().lower() == "unsafe-url":
        findings.append(_finding("header", "Referrer-Policy permissiva (unsafe-url)", WEB_REFERRER_WEAK,
                                 url=url, evidence=f"referrer-policy: {referrer}"))
    return findings


def _valuta_cookie(cookies, url, https):
    """Finding per i cookie privi di flag di sicurezza."""
    findings = []
    for cookie in cookies:
        nome = cookie.get("name", "?")
        if cookie.get("parse_error"):
            continue
        for flag in ("secure", "httponly", "samesite"):
            # il flag Secure ha senso solo su HTTPS
            if flag == "secure" and not https:
                continue
            if not cookie.get(flag):
                regola = WEB_COOKIE_FLAG[flag]
                findings.append(_finding("cookie", f"Cookie '{nome}' senza {flag}", regola,
                                         url=url, evidence=f"set-cookie: {cookie['set_cookie']}"))
    return findings


def _valuta_tecnologie(classi, url):
    """Finding per gli header che rivelano tecnologia/versione."""
    findings = []
    for header, valore in classi.get("tecnologie", {}).items():
        findings.append(_finding("header", f"Divulgazione tecnologia: {header}",
                                 WEB_TECH_DISCLOSURE, url=url, evidence=f"{header}: {valore}"))
    return findings


def _valuta_cve(tecnologie, url, intel):
    """Finding per le tecnologie mappate su NVD (quelle con 'cpe', vedi cve_nvd.arricchisci)
    o riconoscibili ma senza versione. Mai "nessuna vulnerabilità": quando la ricerca non è
    possibile o NVD risponde 0, il finding informativo spiega perché non è una prova."""
    findings = []
    for t in tecnologie:
        nome = t["prodotto"] + (f" {t['versione']}" if t["versione"] else "")
        if not t["versione"]:
            if t["prodotto"].lower() in WEB_TECH_CPE:     # prodotto mappato, versione nascosta
                findings.append(info_finding(
                    "cve", f"{t['prodotto']}: versione non dichiarata",
                    "Il banner non riporta la versione: le CVE non sono determinabili in modo "
                    "passivo (non significa che non ce ne siano).", url=url, evidence=t["evidenza"]))
            continue
        if "cpe" not in t:
            continue
        if "cve_errore" in t:
            findings.append(info_finding("cve", f"{nome}: ricerca CVE non eseguita", t["cve_errore"],
                                         url=url, evidence=t["evidenza"]))
            continue
        cves = t["cve"]
        if not cves:
            findings.append(info_finding(
                "cve", f"{nome}: nessuna CVE in NVD",
                f"NVD non elenca CVE per {t['cpe']}. NVD risponde 0 anche per le versioni assenti "
                "dal suo dizionario: non è una prova di assenza di vulnerabilità.",
                url=url, evidence=t["evidenza"]))
            continue

        peggiori = sorted(cves, key=lambda c: c["punteggio"] or 0, reverse=True)
        impatto = max(WEB_CVE_IMPACT.get((c["gravita"] or "").upper(), WEB_CVE_DEFAULT_IMPACT)
                      for c in cves)
        tetto = WEB_CVE_BACKPORT_MAX_PROBABILITY if t["distro"] else WEB_CVE_MAX_PROBABILITY
        ids = [c["id"] for c in peggiori]
        probabilita, campi = assess_cves(
            intel, ids, WEB_CVE_PROBABILITY,
            cvss_vectors={c["id"]: c["vettore"] for c in cves},
            cvss_scores={c["id"]: c["punteggio"] for c in cves},
            max_probability=tetto)
        probabilita = min(probabilita, tetto)     # anche il valore di ripiego rispetta il tetto

        mostrate = ", ".join(f"{c['id']} ({c['punteggio']})" for c in peggiori[:5])
        if len(cves) > 5:
            mostrate += f" e altre {len(cves) - 5}"
        motivo = f"{mostrate}."
        # la CVE che determina la probabilità può non essere tra le più gravi: va nominata
        if campi.get("probability_cve"):
            fonte = {"kev": "nel catalogo CISA KEV", "epss": "EPSS più alto",
                     "cvss": "vettore CVSS"}[campi["probability_basis"]]
            motivo += f" Probabilità da {campi['probability_cve']} ({fonte})."
        motivo += " Versione ricavata dal solo banner: verificare l'applicabilità su nvd.nist.gov."
        if t["distro"]:
            motivo += (f" Pacchetto di distribuzione ({t['distro']}): le patch di sicurezza vengono "
                       "applicate senza cambiare versione (backport), molte CVE potrebbero essere già "
                       "corrette; probabilità ridotta.")
        findings.append(make_finding(
            "cve", f"{nome} - {len(cves)} CVE note", impatto, probabilita, motivo,
            owasp=OWASP["A06"], url=url, evidence=f"{t['evidenza']} → {t['cpe']}",
            references=ids, service=nome, **campi))
    return findings


def _valuta_tls(tls, url):
    """Finding sulla configurazione TLS: protocolli accettati, validità e scadenza del
    certificato. Protocollo e certificato sono valutati separatamente (recon.ispeziona_tls)."""
    findings = []
    if not tls:
        return findings
    endpoint = tls.get("endpoint", "?")

    # server irraggiungibile o che non parla TLS: niente da valutare, ma va detto nel report
    if "error" in tls:
        findings.append(info_finding("tls", "Ispezione TLS non riuscita", tls["error"],
                                     url=url, evidence=f"handshake TLS con {endpoint} → {tls['error']}"))
        return findings

    # certificato presente ma non attendibile (scaduto, self-signed, hostname errato...)
    if tls.get("cert_valido") is False:
        errore = tls["cert_error"]
        owasp_key, impatto, prob, _ = WEB_TLS_CERT_INVALID
        findings.append(make_finding("tls", "Certificato TLS non valido", impatto, prob,
                                     _motivo_cert(errore), owasp=OWASP[owasp_key], url=url,
                                     evidence=f"handshake TLS con {endpoint}, verifica del certificato "
                                              f"(CA, nome host, scadenza) → {errore}"))

    vecchi = [p for p, accettato in tls.get("protocolli", {}).items()
              if accettato and p in WEB_TLS_WEAK_PROTOCOLS]
    if vecchi:
        elenco = ", ".join(vecchi)
        esiti = "; ".join(f"limitato a {p} → accettato" for p in vecchi)
        findings.append(_finding("tls", f"Protocolli TLS obsoleti accettati: {elenco}", WEB_TLS_OLD,
                                 url=url, evidence=f"handshake TLS con {endpoint}: {esiti}"))

    giorni = tls.get("giorni_a_scadenza")
    if giorni is not None and 0 <= giorni < WEB_TLS_CERT_EXPIRING_DAYS:
        findings.append(_finding("tls", "Certificato TLS in scadenza", WEB_TLS_CERT_EXPIRING,
                                 url=url, evidence=f"handshake TLS con {endpoint}, certificato: "
                                                   f"notAfter {tls.get('not_after')} (tra {giorni} giorni)"))
    return findings


def _motivo_cert(errore):
    """Motivazione specifica del certificato non valido, dedotta dalla stringa d'errore."""
    e = errore.lower()
    if "expired" in e or "has expired" in e:
        return "Certificato TLS scaduto: la connessione non è più garantita."
    # va prima di "self signed": è la radice della catena a non essere attendibile, non il certificato
    if "in certificate chain" in e or "unable to get local issuer" in e:
        return "Catena del certificato TLS con una CA radice non attendibile."
    if "self signed" in e or "self-signed" in e:
        return "Certificato TLS autofirmato: non emesso da una CA attendibile."
    if "hostname" in e or "doesn't match" in e or "no match" in e:
        return "Il certificato TLS non corrisponde al nome host richiesto."
    return WEB_TLS_CERT_INVALID[3]


def valuta_recon(recon_result, intel=None):
    """Lista ordinata di finding web a partire dall'output di recon.recon() (arricchito
    da cve_nvd.arricchisci per le CVE). intel = dati KEV/EPSS per la probabilità delle
    CVE; None = valori di ripiego di config.py.
    Non solleva eccezioni sui problemi del bersaglio: un HTTP fallito diventa un finding
    informativo (serve comunque a dirlo nel report)."""
    url = recon_result.get("target")
    http = recon_result.get("http", {})
    https = _is_https(recon_result)
    findings = []
    richiesta = _richiesta(recon_result)

    if "error" in http:
        findings.append(info_finding("recon", "Richiesta HTTP non riuscita", http["error"],
                                     url=url, evidence=f"richiesta: {richiesta}"))
    else:
        classi = recon_result.get("classi", {})
        da_http = []
        if not https:
            # la risposta finale è arrivata in chiaro: nessun redirect verso HTTPS l'ha impedito
            finale = http.get("final_url", url)
            da_http.append(_finding("http", "Applicazione servita senza HTTPS", WEB_NO_HTTPS, url=url,
                                    evidence=f"URL finale {finale}: nessun redirect verso https://"))
        da_http += (_valuta_header(classi, url, https)
                   + _valuta_header_deboli(classi, url, https)
                   + _valuta_cookie(http.get("cookies", []), url, https)
                   + _valuta_tecnologie(classi, url)
                   + _valuta_cve(recon_result.get("tecnologie_rilevate", []), url, intel))
        # evidenza = richiesta che ha prodotto la risposta + la parte di risposta osservata
        for f in da_http:
            f["evidence"] = f"richiesta: {richiesta} · risposta: {f['evidence']}"
        findings += da_http

    findings += _valuta_tls(recon_result.get("tls"), url)
    return sort_findings(findings)


if __name__ == "__main__":
    import sys
    from . import cve_nvd, recon

    bersaglio = sys.argv[1] if len(sys.argv) > 1 else "https://badssl.com"
    ricognizione = recon.recon(bersaglio)
    cve_nvd.arricchisci(ricognizione.get("tecnologie_rilevate", []))
    risultati = valuta_recon(ricognizione)
    print(f"Bersaglio: {bersaglio}  —  {len(risultati)} finding\n")
    for f in risultati:
        liv = f["level"]
        punteggio = f"{f['score']:>2}" if f["score"] else " ·"
        print(f"  [{punteggio}] {liv:<12} {(f.get('owasp') or ''):<40} {f['item']}")
        print(f"        evidenza: {f.get('evidence')}")
