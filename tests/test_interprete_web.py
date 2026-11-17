"""Test dell'interprete web (interprete_web) e dell'opzione --interpreta di web_report.

Il modello di esempio è costruito con le funzioni vere del motore (web_risk.valuta_recon
su una ricognizione finta, pentest._finding per i finding attivi, build_web_model), senza
alcun accesso di rete (vedi conftest.py e esempi.py).
"""
import pytest

from apocalypsescan_app import percorsi
from apocalypsescan_app.config import OWASP
from apocalypsescan_app.risk import make_finding
from apocalypsescan_app.web import interprete_web as iw
from apocalypsescan_app.web import web_report, web_risk

from esempi import URL, _modello, _ricognizione

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
