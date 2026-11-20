"""Test della tabella unica: finding esterni e interni insieme, colonne Fonte ed Esito PT.

- esito_pt.assegna_esiti: i cinque esiti e il collegamento passivo -> attivo;
- pentest.testa_punto: registra solo le classi provate davvero (con richieste);
- renderer Markdown, HTML, CSV e JSON: stessa tabella, stesse colonne, modelli vecchi ancora leggibili.
"""
import csv
import io
import json
import re

import pytest

from apocalypsescan_app.config import OWASP
from apocalypsescan_app.renderers import csv_out, html_web, json_out, markdown_web
from apocalypsescan_app.risk import info_finding, make_finding
from apocalypsescan_app.web import esito_pt, interprete_web, pentest, web_report

from esempi import _modello, _punto, _ricognizione


def _csp():
    return make_finding("header", "Header mancante: Content-Security-Policy", 3, 3, "Manca la CSP.",
                        owasp=OWASP["A05"], url="https://esempio.it/", evidence="assente")


def _hsts():
    return make_finding("header", "Header mancante: Strict-Transport-Security", 3, 3, "Manca HSTS.",
                        owasp=OWASP["A05"], url="https://esempio.it/", evidence="assente")


def _httponly():
    return make_finding("cookie", "Cookie 'sess' senza HttpOnly", 3, 3, "Leggibile da JS.",
                        owasp=OWASP["A05"], url="https://esempio.it/", evidence="Set-Cookie: sess=...")


def _xss_confermato():
    return pentest._finding(pentest.PT_XSS_REFLECTED, "XSS riflesso su 'q'", _punto("q"), "<svg>",
                            {}, "riflesso", "xss")


def _ssrf():
    return pentest._t_ssrf(None, _punto("url", "https://esempio.it/scarica?url=http://x"))


def _interno():
    return make_finding("database", "MySQL: privilegi globali troppo larghi per 'app'@'%'", 4, 3,
                        "Privilegi ampi.", owasp=OWASP["A01"], url=None,
                        evidence="12 privilegi su *.* (tra cui FILE, SUPER)", fonte="interno",
                        elemento="'app'@'%'", key="mysql-priv-app-%")


# ------------------------------------------------------------------ i cinque esiti

def test_finding_del_pt_confermato_e_ssrf_da_verificare():
    f, ssrf = esito_pt.assegna_esiti([_xss_confermato(), _ssrf()], {"classi_provate": {"xss": 3}})
    assert f["esito_pt"] == "confermato" and f["esito_pt_nota"] is None
    assert ssrf["esito_pt"] == "da verificare" and "verificare a mano" in ssrf["esito_pt_nota"]


def test_finding_interno_non_applicabile():
    (f,) = esito_pt.assegna_esiti([_interno()], {"classi_provate": {"xss": 3}})
    assert f["esito_pt"] == "non applicabile"


def test_passivo_collegato_a_classe_confermata():
    csp, cookie, _ = esito_pt.assegna_esiti([_csp(), _httponly(), _xss_confermato()],
                                            {"classi_provate": {"xss": 3}})
    assert csp["esito_pt"] == "confermato" and "XSS riflesso su 'q'" in csp["esito_pt_nota"]
    assert cookie["esito_pt"] == "confermato"


def test_passivo_collegato_a_classe_provata_senza_conferma():
    (csp,) = esito_pt.assegna_esiti([_csp()], {"classi_provate": {"xss": 4, "sqli": 4}})
    assert csp["esito_pt"] == "non confermato"
    assert "provato su 4 punti di input" in csp["esito_pt_nota"]


def test_passivo_collegato_ma_classe_non_provata():
    (csp,) = esito_pt.assegna_esiti([_csp()], {"classi_provate": {"exposed": 1}})
    assert csp["esito_pt"] == "non testato" and "non provato" in csp["esito_pt_nota"]


def test_passivo_senza_pentest_o_senza_test_corrispondente():
    csp, hsts = esito_pt.assegna_esiti([_csp(), _hsts()], None)
    assert csp["esito_pt"] == "non testato" and "non eseguito" in csp["esito_pt_nota"]
    (hsts,) = esito_pt.assegna_esiti([_hsts()], {"classi_provate": {"xss": 3}})
    assert hsts["esito_pt"] == "non testato" and hsts["esito_pt_nota"] is None


def test_esito_di_ricava_l_esito_dai_modelli_vecchi():
    vecchio_pt = {"source": "pentest", "impact": 4}
    assert esito_pt.esito_di(vecchio_pt) == "confermato"
    assert esito_pt.esito_di({"source": "pentest", "impact": None}) == "da verificare"
    assert esito_pt.esito_di({"source": "header", "impact": 3}) == "non testato"
    assert esito_pt.esito_di({"source": "database", "fonte": "interno"}) == "non applicabile"


# ------------------------------------------------------------------ classi provate dal PT

class ClientFinto:
    """Risponde 200 a tutto con la stessa pagina e conta le richieste."""

    def __init__(self):
        self.n_richieste = 0

    def fetch(self, url, metodo="GET", dati=None, segui_redirect=True):
        self.n_richieste += 1
        return {"status": 200, "headers": {"content-type": "text/html"},
                "text": "<html><body>pagina</body></html>", "url": url, "elapsed": 0.01,
                "error": None}


def test_testa_punto_registra_solo_le_classi_provate_davvero():
    stato = {"time": 0}           # niente sonde lente: SQLi time e command injection non partono
    trovati = pentest.testa_punto(ClientFinto(), _punto("q"), stato)
    assert trovati == []
    provate = {c for c, punti in stato["provate"].items() if punti}
    assert {"sqli", "xss", "ssti", "lfi"} <= provate
    assert "cmdi" not in provate          # nessuna richiesta: budget delle sonde lente a 0
    assert "redirect" not in provate      # 'q' non è un parametro di redirect: test non eseguito
    assert "ssrf" not in provate          # l'SSRF è solo un candidato, senza richieste


def test_penetration_test_espone_le_classi_provate_nel_meta():
    findings, meta = pentest.penetration_test("https://esempio.it/cerca?q=1", crawl_attivo=False,
                                              cli=ClientFinto())
    assert meta["classi_provate"]["xss"] == 1
    assert meta["classi_provate"]["exposed"] == 1
    model = web_report.build_web_model(_ricognizione(), [_csp()] + findings, pentest=meta)
    csp = next(f for f in model["findings"] if "Content-Security-Policy" in f["item"])
    assert csp["esito_pt"] == "non confermato"
    assert model["meta"]["pentest"] is meta


# ------------------------------------------------------------------ la tabella unica

@pytest.fixture
def modello_misto():
    """Un modello con finding esterni (passivi + PT) e un finding interno."""
    findings = [_csp(), _hsts(), _xss_confermato(), _ssrf(), _interno()]
    model = web_report.build_web_model(_ricognizione(), findings, mode=web_report.MODE_VAPT,
                                       host_interno="192.0.2.10",
                                       pentest={"classi_provate": {"xss": 2}, "categorie": {}})
    return model


def _riga_md(md, testo):
    return next(r for r in md.splitlines() if r.startswith("|") and testo in r)


def test_markdown_finding_interno_ed_esterno_nella_stessa_tabella(modello_misto):
    md = markdown_web.render(modello_misto)
    intestazione = ("| # | Fonte | OWASP | Finding | Elemento | Impatto | Probabilità | Rischio | "
                    "Livello | Esito PT | Evidenza | Dettaglio |")
    assert md.count(intestazione) == 1
    sezione = md.split(intestazione, 1)[1].split("\n\n", 1)[0]
    interna = _riga_md(sezione, "privilegi globali troppo larghi")
    esterna = _riga_md(sezione, "XSS riflesso su 'q'")
    csp = _riga_md(sezione, "Content-Security-Policy")
    hsts = _riga_md(sezione, "Strict-Transport-Security")
    assert "| interno |" in interna and "| non applicabile |" in interna and "'app'@'%'" in interna
    assert "| esterno |" in esterna and "| confermato |" in esterna
    assert "| confermato |" in csp and "Esito PT: XSS riflesso confermato" in csp
    assert "| non testato |" in hsts
    ssrf = _riga_md(md, "Possibile SSRF")
    assert "| esterno |" in ssrf and "| da verificare |" in ssrf
    assert "### Esito della verifica di penetration testing" in md


def test_tabella_unica_ordinata_dal_rischio_piu_alto(modello_misto):
    punteggi = [f["score"] for f in modello_misto["findings"] if f["impact"] is not None]
    assert punteggi == sorted(punteggi, reverse=True)
    assert modello_misto["findings"][0]["item"] == "XSS riflesso su 'q'"


def test_riepilogo_per_livello_separa_esterni_e_interni(modello_misto):
    md = markdown_web.render(modello_misto)
    righe = {r.split("|")[1].strip(): [c.strip() for c in r.split("|")[2:5]]
             for r in md.splitlines() if re.match(r"\| (Critico|Alto|Medio|Basso) \| \d", r)}
    interni = sum(int(v[1]) for v in righe.values())
    assert interni == 1
    assert all(int(v[0]) + int(v[1]) == int(v[2]) for v in righe.values())


def test_html_colonne_fonte_esito_e_badge(modello_misto):
    html = html_web.render(modello_misto)
    assert ("<th>Fonte</th><th>OWASP</th><th>Finding</th><th class=\"lungo\">Elemento</th>"
            in html)
    assert "<th>Esito PT</th>" in html
    assert '<span class="esito non-applicabile">non applicabile</span>' in html
    assert '<span class="esito confermato">confermato</span>' in html
    assert '<span class="esito da-verificare">da verificare</span>' in html
    assert '<span class="fonte interno">interno</span>' in html
    assert ".esito.confermato" in html                    # stile presente
    assert 'title="' in html and "interni" in html         # matrice: ripartizione per fonte


def test_csv_colonne_nuove_in_fondo_e_valori(modello_misto):
    testo = csv_out.render(modello_misto)
    righe = list(csv.DictReader(io.StringIO(testo)))
    intestazione = next(csv.reader(io.StringIO(testo)))
    assert intestazione[:3] == ["id", "source", "host"]                  # colonne di prima
    assert intestazione[-7:] == ["owasp", "url", "evidence", "fonte", "elemento", "esito_pt",
                                 "esito_pt_nota"]
    interna = next(r for r in righe if "privilegi" in r["item"])
    assert interna["fonte"] == "interno" and interna["esito_pt"] == "non applicabile"
    assert interna["elemento"] == "'app'@'%'" and interna["host"] == "192.0.2.10"


def test_json_campi_nuovi_e_compatibili(modello_misto):
    dati = json.loads(json_out.render(modello_misto))
    for f in dati["findings"]:
        assert f["fonte"] in ("esterno", "interno")
        assert f["esito_pt"] in ("confermato", "non confermato", "da verificare", "non testato",
                                 "non applicabile")
        # i campi di prima ci sono ancora tutti
        for campo in ("id", "source", "item", "impact", "probability", "score", "level", "owasp",
                      "url", "evidence"):
            assert campo in f


def test_modello_vecchio_senza_campi_nuovi_ancora_leggibile():
    model = _modello()
    for f in model["findings"]:
        for campo in ("fonte", "elemento", "esito_pt", "esito_pt_nota"):
            f.pop(campo)
    md = markdown_web.render(model)
    assert "| esterno |" in md and "| confermato |" in md
    html_web.render(model)
    testo = csv_out.render(model)
    assert ",esterno," in testo
    interprete_web.interpreta_web(model)


def test_interprete_schede_dei_finding_interni(modello_misto):
    lettura = interprete_web.interpreta_web(modello_misto)
    interna = next(s for s in lettura["spiegazioni"] if "privilegi" in s["titolo"])
    assert interna["tipo"] == "db_privilegi"
    assert interna["origine"] == "interno" and interna["esito_pt"] == "non applicabile"
    assert "'app'@'%'" in interna["cosa_significa"]
    md = interprete_web.render_markdown(lettura)
    assert "Esito PT: non applicabile" in md


@pytest.mark.parametrize("f,tipo", [
    (dict(source="database", item="MySQL: utente senza password 'b'@'localhost'"), "db_accesso"),
    (dict(source="database", item="PostgreSQL: accesso senza password (trust) per host all"), "db_accesso"),
    (dict(source="database", item="PostgreSQL: ruolo con SUPERUSER: app"), "db_privilegi"),
    (dict(source="database", item="MySQL: local_infile attivo"), "db_configurazione"),
    (dict(source="servizi", item="Database in ascolto su tutte le interfacce: mysqld (3306/tcp)"), "db_esposto"),
    (dict(source="servizi", item="Servizio superfluo attivo: vsftpd"), "servizio_superfluo"),
    (dict(source="processi", item="Processo dell'applicazione come root: python3"), "app_root"),
    (dict(source="bandit", item="Bandit B105: credenziale scritta nel codice (1)"), "segreto_codice"),
    (dict(source="bandit", item="Bandit B608 hardcoded_sql_expressions (2)"), "codice_statico"),
    (dict(source="file", item="File sensibile leggibile da tutti: .env"), "file_sensibile"),
    (dict(source="webserver", item="nginx dichiara la versione (server_tokens)"), "tecnologia"),
    (dict(source="webserver", item="nginx abilita TLS obsoleto: TLSv1"), "tls_obsoleto"),
    (dict(source="webserver", item="nginx non imposta 3 header di sicurezza"), "ws_header"),
    (dict(source="webserver", item="Apache: metodo TRACE abilitato"), "ws_configurazione"),
    (dict(source="pacchetti", item="nginx 1.18.0 - 3 CVE note", impact=3), "cve"),
])
def test_tipo_dei_finding_interni(f, tipo):
    assert interprete_web.tipo_finding(f) == tipo


def test_info_finding_interno_nei_finding_informativi():
    info = info_finding("servizi", "Porte TCP in ascolto: 2", "80/tcp nginx", owasp=None, url=None,
                        evidence=None, fonte="interno", elemento="porte in ascolto")
    model = web_report.build_web_model(_ricognizione(), [_hsts(), info])
    md = markdown_web.render(model)
    riga = _riga_md(md.split("### Finding informativi", 1)[1], "Porte TCP in ascolto")
    assert riga.startswith("| interno |") and "non applicabile" in riga
