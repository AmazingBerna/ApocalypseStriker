"""Test del report HTML web (renderers/html_web) e del formato html di web_report."""
import re
from html.parser import HTMLParser

import pytest

from apocalypsescan_app import percorsi
from apocalypsescan_app.renderers import html_web
from apocalypsescan_app.web import interprete_web as iw
from apocalypsescan_app.web import web_report, web_risk

from esempi import URL, _modello, _ricognizione


class _Controllo(HTMLParser):
    """Raccoglie tag e attributi per verificare che il documento sia autonomo."""

    def __init__(self):
        super().__init__()
        self.tag = []
        self.attributi = []

    def handle_starttag(self, tag, attrs):
        self.tag.append(tag)
        self.attributi += attrs


def _analizza(testo):
    controllo = _Controllo()
    controllo.feed(testo)
    return controllo


def test_report_html_completo():
    testo = html_web.render(_modello())
    assert testo.startswith("<!doctype html>")
    for sezione in ("Report Automatico di VAPT Web", "Ricognizione passiva", "Tabella dei rischi",
                    "Matrice di rischio", "Elenco dei finding", "Portata dell'analisi",
                    "Note metodologiche"):
        assert sezione in testo
    assert "Spiegazione guidata" not in testo        # senza lettura, niente spiegazione


def test_report_html_autonomo_e_senza_script():
    """Nessuno script e nessuna risorsa esterna: si apre offline e non esegue nulla."""
    controllo = _analizza(html_web.render(_modello(), iw.interpreta_web(_modello())))
    assert "script" not in controllo.tag
    assert "link" not in controllo.tag and "img" not in controllo.tag
    for nome, valore in controllo.attributi:
        assert not nome.startswith("on"), nome
        if nome in ("src", "href"):
            assert valore.startswith("#"), valore   # solo ancore interne


def test_payload_del_pentest_sono_escapati():
    """Le evidenze del pentest contengono payload (<svg>, {{7*7}}): nel report sono testo."""
    testo = html_web.render(_modello())
    assert "<svg>" not in testo
    assert "&lt;svg&gt;" in testo


def test_report_html_con_spiegazione():
    model = _modello(con_csrf_idor=True)
    lettura = iw.interpreta_web(model)
    testo = html_web.render(model, lettura)
    assert 'id="spiegazione"' in testo
    for voce in ("Cosa significa", "Come viene attaccata", "Cosa fare", "Da verificare a mano"):
        assert voce in testo
    # una scheda per ogni finding valutato e per ogni indizio da verificare
    assert testo.count('class="scheda"') == len(lettura["spiegazioni"]) + len(lettura["da_verificare"])


def test_modello_senza_finding():
    model = {"meta": {"target": URL, "generated_at": "2026-11-17T10:00:00", "mode": "VA",
                      "host": "esempio.it", "tool": "test"},
             "tecnologie": {}, "tecnologie_rilevate": [], "tls": None, "findings": []}
    testo = html_web.render(model, iw.interpreta_web(model))
    assert "Nessun finding valutabile" in testo
    assert re.search(r"<title>VAPT web - https://esempio.it/</title>", testo)


# --------------------------------------------------------------------------
# web_report --format html
# --------------------------------------------------------------------------

@pytest.fixture
def reports_temporanei(tmp_path, monkeypatch):
    cartella = tmp_path / "reports"
    monkeypatch.setattr(percorsi, "REPORTS", cartella)

    def finta(url, nvd=True, progress=None):
        ricognizione = _ricognizione()
        return ricognizione, web_risk.valuta_recon(ricognizione), None
    monkeypatch.setattr(web_report, "_esegui_va", finta)
    return cartella


def test_formato_html_accettato():
    assert web_report.parse_formati_web("md,html,json,csv") == ["md", "html", "json", "csv"]


def test_html_salvato_in_reports_html(reports_temporanei):
    web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd",
                     "--format", "md,html", "--output", "audit_html"])
    html = reports_temporanei / "html" / "audit_html.html"
    assert html.is_file()
    assert (reports_temporanei / "md" / "audit_html.md").is_file()
    assert "Spiegazione guidata" not in html.read_text(encoding="utf-8")


def test_html_con_interpreta_include_spiegazione(reports_temporanei, capsys):
    web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd",
                     "--format", "html", "--output", "audit_html", "--interpreta"])
    testo = (reports_temporanei / "html" / "audit_html.html").read_text(encoding="utf-8")
    assert 'id="spiegazione"' in testo
    assert (reports_temporanei / "md" / "audit_html_interpretazione.md").is_file()
