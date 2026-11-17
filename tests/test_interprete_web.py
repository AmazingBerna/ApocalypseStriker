"""Test dell'interprete web (interprete_web) e dell'opzione --interpreta di web_report.

Il modello di esempio è costruito con le funzioni vere del motore (web_risk.valuta_recon
su una ricognizione finta, pentest._finding per i finding attivi, build_web_model), senza
alcun accesso di rete (vedi conftest.py).
"""
import pytest

from apocalypsescan_app import percorsi
from apocalypsescan_app.config import OWASP
from apocalypsescan_app.risk import make_finding
from apocalypsescan_app.web import interprete_web as iw
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
    model = web_report.build_web_model(ricognizione, findings, mode=web_report.MODE_VAPT)
    model["meta"]["autorizzazione"] = {"ambiente": "test", "confermata_il": "2026-11-17T10:00:00",
                                       "modo": "interattiva"}
    model["meta"]["pentest"] = {"eseguito": True, "crawl": True, "pagine": 3, "punti_input": 9,
                                "richieste": 120, "troncato": False,
                                "categorie": dict(pentest.PT_CATEGORIE_TESTATE)}
    return model


# --------------------------------------------------------------------------
# interpreta_web
# --------------------------------------------------------------------------

TIPI_ATTESI = {"sqli", "xss", "cmdi", "ssti", "lfi", "redirect", "exposed",          # attivi
               "csp", "hsts", "xfo", "xcto", "cookie_secure", "cookie_httponly",      # passivi
               "cookie_samesite", "tls_obsoleto", "tecnologia", "cve"}


def test_lettura_completa_attivi_e_passivi():
    lettura = iw.interpreta_web(_modello())
    assert lettura["verdetto"]["livello"] == "Critico"
    assert lettura["verdetto"]["testo"]
    assert sum(lettura["conteggi"].values()) == len(lettura["spiegazioni"])
    assert lettura["punti_chiave"]
    assert 0 < len(lettura["priorita"]) <= iw.MAX_PRIORITA
    # priorità = i finding a rischio più alto, in ordine
    punteggi = [s["score"] for s in lettura["spiegazioni"]]
    assert punteggi == sorted(punteggi, reverse=True)
    assert [s["score"] for s in lettura["priorita"]] == punteggi[:len(lettura["priorita"])]
    # ogni tipo atteso è riconosciuto, con le tre voci non vuote e il perché del livello
    tipi = {s["tipo"] for s in lettura["spiegazioni"]}
    assert TIPI_ATTESI <= tipi
    for s in lettura["spiegazioni"]:
        assert s["tipo"] in iw.SCHEDE, s["titolo"]
        for voce in ("cosa_significa", "come_attaccano", "cosa_fare", "perche"):
            assert s[voce] and s[voce].strip(), (s["tipo"], voce)
    # l'avvertenza generale chiude sempre i limiti
    assert lettura["limiti"][-1] == iw.AVVERTENZA_FINALE


def test_ssrf_candidata_da_verificare():
    """La SSRF è un indizio non valutato: non è tra i finding valutati ma tra quelli da
    verificare a mano, con la sua scheda."""
    lettura = iw.interpreta_web(_modello())
    assert "ssrf" not in {s["tipo"] for s in lettura["spiegazioni"]}
    ssrf = [s for s in lettura["da_verificare"] if s["tipo"] == "ssrf"]
    assert len(ssrf) == 1
    assert all(ssrf[0][v] for v in ("cosa_significa", "come_attaccano", "cosa_fare"))


def test_classe_letta_dall_id():
    """Nel modello la key non c'è più: la classe si ricava dall'id."""
    model = _modello()
    attivo = next(f for f in model["findings"] if f["item"].startswith("SQL injection"))
    assert "key" not in attivo
    assert iw.classe_pentest(attivo) == "sqli"


def test_testi_presi_dal_finding():
    """Le parti variabili vengono dal finding (parametro, cookie, protocolli, CVE)."""
    per_tipo = {s["tipo"]: s for s in iw.interpreta_web(_modello())["spiegazioni"]}
    assert "'id'" in per_tipo["sqli"]["cosa_significa"]
    assert "'sessione'" in per_tipo["cookie_secure"]["cosa_significa"]
    assert "TLSv1" in per_tipo["tls_obsoleto"]["cosa_significa"]
    assert "CVE-2017-7529" in per_tipo["cve"]["cosa_significa"]
    assert "/.env" in per_tipo["exposed"]["cosa_significa"]


def test_csrf_idor_assenti_non_compaiono():
    lettura = iw.interpreta_web(_modello(con_csrf_idor=False))
    tipi = {s["tipo"] for s in lettura["spiegazioni"] + lettura["da_verificare"]}
    assert not tipi & {"csrf", "idor"}
    corpo = iw.render_markdown(lettura).split("## Cosa questa lettura")[0]
    assert iw.SCHEDE["csrf"].nome not in corpo
    assert iw.SCHEDE["idor"].nome not in corpo


def test_csrf_idor_presenti_hanno_scheda():
    lettura = iw.interpreta_web(_modello(con_csrf_idor=True))
    per_tipo = {s["tipo"]: s for s in lettura["spiegazioni"]}
    for tipo in ("csrf", "idor"):
        assert tipo in per_tipo
        assert all(per_tipo[tipo][v] for v in ("cosa_significa", "come_attaccano", "cosa_fare"))
    assert "'doc'" in per_tipo["idor"]["cosa_significa"]


@pytest.mark.parametrize("tipo", sorted(iw.SCHEDE))
def test_ogni_scheda_ha_tre_voci(tipo):
    """Anche un finding con i soli campi minimi produce tre voci non vuote, senza segnaposto
    rimasti nel testo."""
    f = {"source": "pentest", "item": "x", "reason": "motivo", "impact": 3, "probability": 3,
         "score": 9, "level": "Medio", "references": []}
    scheda = iw.SCHEDE[tipo]
    campi = iw.campi_finding(f)
    for voce in (scheda.cosa_significa, scheda.come_attaccano, scheda.cosa_fare):
        testo = iw._voce(voce, f, campi)
        assert testo.strip()
        assert "{" not in testo.replace("{{", "")


def test_modello_senza_finding():
    for model in ({"meta": {}, "findings": []}, {"findings": []}, {}):
        lettura = iw.interpreta_web(model)
        assert lettura["verdetto"]["livello"] == "Nessuno"
        assert lettura["priorita"] == [] and lettura["spiegazioni"] == []
        assert lettura["limiti"][-1] == iw.AVVERTENZA_FINALE
        assert "# Interpretazione del report web" in iw.render_markdown(lettura)


def test_tipo_sconosciuto_usa_motivazione():
    f = make_finding("pentest", "Qualcosa di nuovo", 3, 3, "Motivazione del finding.",
                     owasp=OWASP["A07"], key="pt-nuovaclasse-x")
    s = iw.spiega(f)
    assert s["tipo"] is None
    assert s["cosa_significa"] == "Motivazione del finding."
    assert s["come_attaccano"] == iw.ATTACCO_OWASP["A07"]
    assert s["cosa_fare"]


def test_solo_va_passivo_segnala_pentest_non_eseguito():
    model = _modello()
    del model["meta"]["pentest"]
    lettura = iw.interpreta_web(model)
    assert any("--pentest" in lim for lim in lettura["limiti"])


def test_markdown_e_terminale(capsys):
    lettura = iw.interpreta_web(_modello())
    md = iw.render_markdown(lettura)
    for sezione in ("## In sintesi", "## Da dove cominciare", "**Come viene attaccata.**",
                    "## Da verificare a mano", "## Cosa questa lettura non copre"):
        assert sezione in md
    iw.print_interpretazione(lettura, "reports/md/x_interpretazione.md")
    uscita = capsys.readouterr().out
    assert "COSA SIGNIFICA" in uscita and "Come viene attaccata" in uscita


# --------------------------------------------------------------------------
# web_report --interpreta: stesso nome per report e interpretazione
# --------------------------------------------------------------------------

@pytest.fixture
def reports_temporanei(tmp_path, monkeypatch):
    cartella = tmp_path / "reports"
    monkeypatch.setattr(percorsi, "REPORTS", cartella)
    return cartella


def _scansione_finta(monkeypatch):
    """_esegui_va senza rete: restituisce la ricognizione e i finding di esempio."""
    def finta(url, nvd=True, progress=None):
        ricognizione = _ricognizione()
        return ricognizione, web_risk.valuta_recon(ricognizione), None
    monkeypatch.setattr(web_report, "_esegui_va", finta)


def test_nome_report_usato_anche_per_interpretazione(reports_temporanei, monkeypatch, capsys):
    _scansione_finta(monkeypatch)
    esito = web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd",
                             "--format", "md,json", "--output", "audit_cliente", "--interpreta"])
    assert esito == 0
    assert (reports_temporanei / "md" / "audit_cliente.md").is_file()
    assert (reports_temporanei / "json" / "audit_cliente.json").is_file()
    interpretazione = reports_temporanei / "md" / "audit_cliente_interpretazione.md"
    assert interpretazione.is_file()
    testo = interpretazione.read_text(encoding="utf-8")
    assert "# Interpretazione del report web" in testo and URL in testo
    uscita = capsys.readouterr().out
    assert "COSA SIGNIFICA" in uscita
    assert "audit_cliente_interpretazione.md" in uscita


def test_senza_interpreta_nessuna_interpretazione(reports_temporanei, monkeypatch):
    _scansione_finta(monkeypatch)
    web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd",
                     "--output", "solo_report"])
    assert (reports_temporanei / "md" / "solo_report.md").is_file()
    assert not (reports_temporanei / "md" / "solo_report_interpretazione.md").exists()
