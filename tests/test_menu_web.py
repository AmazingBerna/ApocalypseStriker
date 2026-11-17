"""Test della scansione guidata (menu_web): passo "Nome del report" e inoltro di --output.

Nessun accesso di rete: subprocess.run viene sostituito e input() è simulato.
"""
import builtins

import pytest

from apocalypsescan_app import menu_web


# --------------------------------------------------------------------------
# valida_nome_report
# --------------------------------------------------------------------------

@pytest.mark.parametrize("nome", ["web_20261117_101500", "Report-WSL", "audit_2026", "réport"])
def test_nome_valido(nome):
    assert menu_web.valida_nome_report(nome) is None


@pytest.mark.parametrize("nome", [
    "",                     # vuoto
    "cartella/report",      # separatore POSIX
    "cartella\\report",     # separatore Windows
    "../report",            # risalita
    "report.md",            # estensione
    "report.json",
    "-report",              # sembrerebbe un'opzione
    "con spazio",
    "a:b",
])
def test_nome_non_valido(nome):
    assert menu_web.valida_nome_report(nome)


def test_nome_predefinito_valido():
    nome = menu_web.nome_report_predefinito()
    assert nome.startswith("web_")
    assert menu_web.valida_nome_report(nome) is None


# --------------------------------------------------------------------------
# comando_web
# --------------------------------------------------------------------------

def test_comando_web_con_output():
    argv, mostrato = menu_web.comando_web("https://esempio.it/", "test", True, ["md"],
                                          output="mio_report")
    i = argv.index("--output")
    assert argv[i + 1] == "mio_report"
    assert "--output mio_report" in mostrato


def test_comando_web_senza_output():
    argv, mostrato = menu_web.comando_web("https://esempio.it/", "test", True, ["md"])
    assert "--output" not in argv
    assert "--output" not in mostrato


def test_comando_web_resto_invariato():
    """Aggiungere output non cambia le altre opzioni."""
    base, _ = menu_web.comando_web("https://esempio.it/", "test", False, ["md", "json"],
                                   pentest=True, crawl=False)
    con, _ = menu_web.comando_web("https://esempio.it/", "test", False, ["md", "json"],
                                  pentest=True, crawl=False, output="x")
    assert con[:len(base)] == base
    assert con[len(base):] == ["--output", "x"]


# --------------------------------------------------------------------------
# esegui_scansione: flusso completo con risposte simulate
# --------------------------------------------------------------------------

def _simula(monkeypatch, risposte):
    """input() restituisce le risposte nell'ordine; subprocess.run registra l'argv."""
    coda = iter(risposte)
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: next(coda))
    lanciati = []
    monkeypatch.setattr(menu_web.subprocess, "run", lambda argv, *a, **k: lanciati.append(argv))
    return lanciati


def test_scansione_guidata_nome_scelto(monkeypatch, capsys):
    lanciati = _simula(monkeypatch, [
        "https://esempio.it",   # URL
        "",                     # ambiente: default
        "",                     # solo VA passivo
        "n",                    # niente NVD
        "",                     # formati: default (md)
        "report/sbagliato",     # nome non valido -> ripetuto
        "report.md",            # nome non valido -> ripetuto
        "audit_cliente",        # nome valido
        "n",                    # niente spiegazione guidata
        "s",                    # lanciarlo adesso
        "",                     # pausa
    ])
    menu_web.esegui_scansione()
    assert len(lanciati) == 1
    argv = lanciati[0]
    assert argv[argv.index("--output") + 1] == "audit_cliente"
    assert "--interpreta" not in argv
    assert "audit_cliente" in capsys.readouterr().out


def test_scansione_guidata_nome_predefinito(monkeypatch):
    monkeypatch.setattr(menu_web, "nome_report_predefinito", lambda: "web_20261117_120000")
    # nome e spiegazione guidata lasciati al default (Invio): la spiegazione è attiva
    lanciati = _simula(monkeypatch, ["https://esempio.it", "", "", "n", "", "", "", "s", ""])
    menu_web.esegui_scansione()
    argv = lanciati[0]
    assert argv[argv.index("--output") + 1] == "web_20261117_120000"
    assert "--interpreta" in argv


def test_comando_web_interpreta():
    argv, mostrato = menu_web.comando_web("https://esempio.it/", "test", True, ["md"],
                                          output="x", interpreta=True)
    assert argv[-3:] == ["--output", "x", "--interpreta"]
    assert mostrato.endswith("--output x --interpreta")
    argv, _ = menu_web.comando_web("https://esempio.it/", "test", True, ["md"])
    assert "--interpreta" not in argv


# --------------------------------------------------------------------------
# Formati: HTML selezionabile, JSON sempre salvato dalla scansione guidata
# --------------------------------------------------------------------------

def _formato(argv):
    return argv[argv.index("--format") + 1]


def test_formati_html_e_json_sempre(monkeypatch):
    # formati lasciati al default (Markdown + HTML): il JSON si aggiunge da solo
    lanciati = _simula(monkeypatch, ["https://esempio.it", "", "", "n", "", "", "n", "s", ""])
    menu_web.esegui_scansione()
    assert _formato(lanciati[0]) == "md,html,json"


@pytest.mark.parametrize("scelta, attesi", [("1", "md,json"), ("2", "html,json"),
                                            ("3", "md,html,json"), ("4", "md,html,csv,json")])
def test_ogni_preset_dei_formati(monkeypatch, scelta, attesi):
    lanciati = _simula(monkeypatch, ["https://esempio.it", "", "", "n", scelta, "", "n", "s", ""])
    menu_web.esegui_scansione()
    assert _formato(lanciati[0]) == attesi


def test_formati_scansione_non_duplica_json():
    assert menu_web.formati_scansione(["md", "json"]) == ["md", "json"]
    assert menu_web.formati_scansione(["html"]) == ["html", "json"]


# --------------------------------------------------------------------------
# Voce "Interpreta report"
# --------------------------------------------------------------------------

def test_voce_interpreta_report_nel_menu():
    voce = next(v for v in menu_web.VOCI if v.etichetta == "Interpreta report")
    assert voce.azione is menu_web.interpreta_report


@pytest.fixture
def reports_temporanei(tmp_path, monkeypatch):
    from apocalypsescan_app import percorsi
    cartella = tmp_path / "reports"
    monkeypatch.setattr(percorsi, "REPORTS", cartella)
    return cartella


def _salva_json(cartella, nome, testo):
    (cartella / "json").mkdir(parents=True, exist_ok=True)
    percorso = cartella / "json" / f"{nome}.json"
    percorso.write_text(testo, encoding="utf-8", newline="\n")
    return percorso


def test_interpreta_report_senza_report(reports_temporanei, monkeypatch, capsys):
    _simula(monkeypatch, [""])            # solo la pausa
    menu_web.interpreta_report()
    assert "Nessun report JSON" in capsys.readouterr().out


def test_interpreta_report_genera_spiegazione(reports_temporanei, monkeypatch, capsys):
    from apocalypsescan_app.renderers import json_out
    from esempi import _modello
    _salva_json(reports_temporanei, "audit_cliente", json_out.render(_modello()))
    _simula(monkeypatch, ["1", ""])       # primo report, pausa
    menu_web.interpreta_report()
    uscita = capsys.readouterr().out
    assert "audit_cliente" in uscita and "COSA SIGNIFICA" in uscita
    assert (reports_temporanei / "md" / "audit_cliente_interpretazione.md").is_file()


def test_interpreta_report_json_non_valido(reports_temporanei, monkeypatch, capsys):
    _salva_json(reports_temporanei, "rotto", "{non è json")
    _simula(monkeypatch, ["1", ""])
    menu_web.interpreta_report()
    assert "non è un report web" in capsys.readouterr().out
    assert not (reports_temporanei / "md" / "rotto_interpretazione.md").exists()
