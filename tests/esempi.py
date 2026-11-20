"""Modello di esempio condiviso dai test: costruito con le funzioni vere del motore
(web_risk.valuta_recon su una ricognizione finta, pentest._finding, build_web_model),
senza alcun accesso di rete."""
from apocalypsescan_app.config import OWASP
from apocalypsescan_app.risk import make_finding
from apocalypsescan_app.web import pentest, web_report, web_risk

URL = "https://esempio.it/"


def _ricognizione():
    """Output finto di recon.recon(): header mancanti, cookie senza flag, TLS vecchio,
    banner con versione e una CVE (già "arricchita" come farebbe cve_nvd)."""
    return {
        "host": "esempio.it",
        "target": URL,
        "http": {"status": 200, "final_url": URL, "redirected": False,
                 "cookies": [{"name": "sessione", "set_cookie": "sessione=abc; Path=/",
                              "secure": False, "httponly": False, "samesite": None}]},
        "classi": {
            "security_mancanti": {"content-security-policy": None,
                                  "strict-transport-security": None,
                                  "x-frame-options": None,
                                  "x-content-type-options": None},
            "security_presenti": {},
            "dettaglio": {},
            "tecnologie": {"server": "nginx/1.10.3"},
        },
        "tecnologie_rilevate": [{
            "prodotto": "nginx", "versione": "1.10.3", "fonte": "header server",
            "evidenza": "server: nginx/1.10.3", "distro": None, "mappato": True,
            "cpe": "cpe:2.3:a:f5:nginx:1.10.3:*:*:*:*:*:*:*",
            "cve": [{"id": "CVE-2017-7529", "punteggio": 7.5, "gravita": "HIGH",
                     "vettore": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        }],
        "tls": {"endpoint": "esempio.it:443", "protocolli": {"TLSv1": True, "TLSv1.2": True},
                "cert_valido": True, "giorni_a_scadenza": 200},
    }


def _punto(parametro, origine="https://esempio.it/cerca?q=1"):
    return {"metodo": "GET", "azione": "https://esempio.it/cerca", "bersaglio": parametro,
            "origine": origine, "parametri": {parametro: "1"}}


def _finding_attivi(con_csrf_idor=False):
    """Finding del penetration testing come li produce pentest.py (key pt-<classe>-...)."""
    f = pentest._finding
    attivi = [
        f(pentest.PT_SQLI_ERROR, "SQL injection su 'id'", _punto("id"), "'", {}, "errore SQL", "sqli"),
        f(pentest.PT_XSS_REFLECTED, "XSS riflesso su 'q'", _punto("q"), "<svg>", {}, "riflesso", "xss"),
        f(pentest.PT_CMDI, "Command injection su 'host'", _punto("host"), ";sleep 5", {}, "ritardo", "cmdi"),
        f(pentest.PT_SSTI, "Server-Side Template Injection su 'nome'", _punto("nome"), "{{7*7}}", {},
          "49", "ssti"),
        f(pentest.PT_PATH_TRAVERSAL, "Path traversal su 'file'", _punto("file"), "../../etc/passwd", {},
          "letto /etc/passwd", "lfi"),
        f(pentest.PT_OPEN_REDIRECT, "Open redirect su 'next'", _punto("next"), "//example.org", {},
          "redirect", "redirect"),
        make_finding("pentest", "File sensibile esposto: /.env", *pentest.PT_EXPOSED_FILE[1:3],
                     pentest.PT_EXPOSED_FILE[3], owasp=OWASP["A05"], url="https://esempio.it/.env",
                     evidence="richiesta: GET /.env · risposta: 200", key="pt-exposed-/.env"),
        pentest._t_ssrf(None, _punto("url", "https://esempio.it/scarica?url=http://x")),
    ]
    if con_csrf_idor:
        # rilevamento ancora da fare (altro branch): stessa forma dei finding attivi
        attivi += [
            make_finding("pentest", "Form senza token anti-CSRF: /profilo", 4, 3, "Manca il token.",
                         owasp=OWASP["A01"], url="https://esempio.it/profilo",
                         evidence="richiesta: POST /profilo", key="pt-csrf-/profilo"),
            make_finding("pentest", "Accesso a oggetti altrui su 'doc'", 4, 4, "Oggetto altrui letto.",
                         owasp=OWASP["A01"], url="https://esempio.it/doc?doc=2",
                         evidence="richiesta: GET /doc?doc=2", key="pt-idor-doc", service="doc"),
        ]
    return attivi


def _modello(con_csrf_idor=False):
    ricognizione = _ricognizione()
    findings = web_risk.valuta_recon(ricognizione) + _finding_attivi(con_csrf_idor)
    meta_pt = {"eseguito": True, "crawl": True, "pagine": 3, "punti_input": 9,
               "richieste": 120, "troncato": False,
               "categorie": dict(pentest.PT_CATEGORIE_TESTATE),
               "classi_provate": {"sqli": 9, "xss": 9, "cmdi": 9, "ssti": 9, "lfi": 9,
                                  "redirect": 1, "exposed": 1}}
    model = web_report.build_web_model(ricognizione, findings, mode=web_report.MODE_VAPT,
                                       pentest=meta_pt)
    model["meta"]["autorizzazione"] = {"ambiente": "test", "confermata_il": "2026-11-17T10:00:00",
                                       "modo": "interattiva"}
    return model
