"""Test dei comandi `apocalypse inspect` e `apocalypse attack <url> --inspect`.

La connessione è sostituita dalla macchina finta (macchina_finta.py): nessun SSH vero.
I report finiscono in una cartella temporanea.
"""
import argparse
import json
from datetime import datetime

import pytest

from apocalypsescan_app import cli, percorsi
from apocalypsescan_app.interno import comando
from apocalypsescan_app.interno.comandi import EsecutoreSolaLettura
from apocalypsescan_app.remote import LocalExecutor, SSHExecutor
from apocalypsescan_app.web import web_report, web_risk

from esempi import URL, _ricognizione
from macchina_finta import DB_PASSWORD, ENV, SEGRETO_NEL_CODICE, SUDO_PASSWORD, MacchinaFinta

OPZIONI_SSH = ["--host", "192.0.2.10", "--user", "auditor", "--code", "/var/www/app"]


@pytest.fixture
def macchine():
    """Le macchine finte create durante il test (una per ogni connessione aperta)."""
    return []


@pytest.fixture
def ambiente(tmp_path, monkeypatch, macchine):
    """Report in una cartella temporanea, credenziali nelle variabili d'ambiente, macchina finta
    al posto della connessione SSH. Restituisce la cartella dei report."""
    cartella = tmp_path / "reports"
    monkeypatch.setattr(percorsi, "REPORTS", cartella)
    for nome, valore in ENV.items():
        monkeypatch.setenv(nome, valore)
    def crea_finto(conn, env=None):
        macchine.append(MacchinaFinta())
        return EsecutoreSolaLettura(macchine[-1])
    monkeypatch.setattr(comando, "crea_esecutore", crea_finto)

    def va_finta(url, nvd=True, progress=None):
        ricognizione = _ricognizione()
        return ricognizione, web_risk.valuta_recon(ricognizione), None
    monkeypatch.setattr(web_report, "_esegui_va", va_finta)
    return cartella


def _leggi_tutti(cartella):
    return {p.name: p.read_text(encoding="utf-8-sig") for p in cartella.rglob("*.*")}


# ------------------------------------------------------------------ apocalypse inspect

def test_inspect_scrive_il_report_interno_in_tutti_i_formati(ambiente):
    codice = comando.main(OPZIONI_SSH + ["--env", "test", "--yes", "--no-banner", "--no-nvd",
                                         "--format", "md,html,json,csv", "--output", "audit_int"])
    assert codice == 0
    for fmt in ("md", "html", "json", "csv"):
        assert (ambiente / fmt / f"audit_int.{fmt}").is_file()
    md = (ambiente / "md" / "audit_int.md").read_text(encoding="utf-8")
    assert md.startswith("# Report Automatico di Analisi Interna")
    assert "## Analisi interna (accesso autorizzato, sola lettura)" in md
    assert "Ricognizione passiva" not in md and "Portata dell'analisi" not in md
    assert "MySQL: privilegi globali troppo larghi per 'app'@'%'" in md
    modello = json.loads((ambiente / "json" / "audit_int.json").read_text(encoding="utf-8"))
    assert modello["meta"]["analisi_web"] is False
    assert modello["meta"]["interno"]["bersaglio"] == "ssh://auditor@192.0.2.10:22"
    assert modello["meta"]["autorizzazione"]["utente"] == "auditor"
    assert modello["findings"] and all(f["fonte"] == "interno" for f in modello["findings"])
    assert all(f["host"] == "192.0.2.10" for f in modello["findings"])
    html = (ambiente / "html" / "audit_int.html").read_text(encoding="utf-8")
    assert "Report Automatico di Analisi Interna" in html and "Ricognizione passiva" not in html


def test_inspect_mai_credenziali_o_segreti_in_report_e_terminale(ambiente, capsys):
    comando.main(OPZIONI_SSH + ["--env", "test", "--yes", "--no-banner", "--no-nvd",
                                "--format", "md,html,json,csv", "--output", "segreti",
                                "--interpreta"])
    uscita = capsys.readouterr()
    testi = list(_leggi_tutti(ambiente).values()) + [uscita.out, uscita.err]
    assert len(testi) >= 6        # 4 formati + interpretazione + terminale
    for testo in testi:
        for segreto in (DB_PASSWORD, SUDO_PASSWORD, SEGRETO_NEL_CODICE):
            assert segreto not in testo


def test_nessuna_opzione_per_le_password(ambiente):
    for opzione in ("--db-password", "--password", "--sudo-password", "--db-user"):
        with pytest.raises(SystemExit) as e:
            comando.main(OPZIONI_SSH + [opzione, "x", "--env", "test", "--yes", "--no-banner"])
        assert e.value.code == 2


def test_inspect_con_yes_richiede_env(ambiente):
    with pytest.raises(SystemExit) as e:
        comando.main(OPZIONI_SSH + ["--yes", "--no-banner"])
    assert e.value.code == 2


def test_cli_smista_inspect(ambiente):
    codice = cli.main(["inspect"] + OPZIONI_SSH + ["--env", "test", "--yes", "--no-banner",
                                                   "--no-nvd", "--output", "da_cli"])
    assert codice == 0 and (ambiente / "md" / "da_cli.md").is_file()


def test_inspect_connessione_fallita_esce_con_errore(ambiente, monkeypatch, capsys):
    monkeypatch.setattr(comando, "crea_esecutore",
                        lambda conn, env=None: EsecutoreSolaLettura(MacchinaFinta(connessione=False)))
    codice = comando.main(OPZIONI_SSH + ["--env", "test", "--yes", "--no-banner", "--no-nvd",
                                         "--output", "ko"])
    assert codice == 1
    assert "connessione non riuscita" in capsys.readouterr().out
    assert (ambiente / "md" / "ko.md").is_file()      # il report dice cosa non è stato fatto


# ------------------------------------------------------------------ autorizzazione

def test_prompt_mostra_host_utente_e_data_ma_non_le_password(capsys):
    conn = {"host": "192.0.2.10", "user": "auditor", "key": None, "port": 22}
    esecutore = EsecutoreSolaLettura(MacchinaFinta())
    with pytest.raises(SystemExit) as e:
        comando.confirm_inspect(conn, esecutore, "/var/www/app", env=ENV, leggi=lambda _: "no")
    assert e.value.code == 0
    testo = capsys.readouterr().out
    assert "192.0.2.10" in testo and "auditor" in testo
    assert datetime.now().strftime("%Y-%m-%d") in testo
    assert "credenziali presenti" in testo and "password presente" in testo
    assert DB_PASSWORD not in testo and SUDO_PASSWORD not in testo


def test_prompt_confermato_restituisce_i_dati_dell_autorizzazione():
    conn = {"host": "192.0.2.10", "user": "auditor", "key": None, "port": 22}
    dati = comando.confirm_inspect(conn, EsecutoreSolaLettura(MacchinaFinta()), env={},
                                   leggi=lambda _: "si")
    assert dati["host"] == "192.0.2.10" and dati["utente"] == "auditor"
    assert dati["modo"] == "interattiva"


# ------------------------------------------------------------------ parametri di connessione

def _args(**kw):
    base = {"host": None, "user": None, "key": None, "port": 22, "code": None, "semgrep_rules": None}
    base.update(kw)
    return argparse.Namespace(**base)


def test_parametri_da_variabili_d_ambiente(tmp_path):
    chiave = tmp_path / "id_ed25519"
    chiave.write_text("finta", encoding="utf-8")
    env = {"APOCALYPSE_SSH_HOST": "192.0.2.20", "APOCALYPSE_SSH_USER": "audit",
           "APOCALYPSE_SSH_KEY": str(chiave)}
    conn = comando.parametri_connessione(_args(), env)
    assert conn == {"host": "192.0.2.20", "user": "audit", "key": str(chiave), "port": 22}
    # gli argomenti vincono sulle variabili d'ambiente
    assert comando.parametri_connessione(_args(host="192.0.2.30"), env)["host"] == "192.0.2.30"


def test_parametri_errori_guidati(tmp_path):
    with pytest.raises(comando.ErroreParametri, match="--user"):
        comando.parametri_connessione(_args(host="192.0.2.10"), {})
    with pytest.raises(comando.ErroreParametri, match="chiave SSH non trovata"):
        comando.parametri_connessione(_args(host="192.0.2.10", user="a",
                                            key=str(tmp_path / "manca")), {})
    with pytest.raises(comando.ErroreParametri, match="--code"):
        comando.parametri_connessione(_args(code="var/www"), {})
    with pytest.raises(comando.ErroreParametri, match="--semgrep-rules"):
        comando.parametri_connessione(_args(semgrep_rules="auto"), {})


def test_senza_host_analisi_locale():
    conn = comando.parametri_connessione(_args(), {})
    assert conn["host"] is None
    esecutore = comando.crea_esecutore(conn, {})
    assert isinstance(esecutore, EsecutoreSolaLettura)
    assert isinstance(esecutore._executor, LocalExecutor)


def test_esecutore_ssh_con_password_sudo_solo_da_ambiente():
    conn = {"host": "192.0.2.10", "user": "auditor", "key": None, "port": 2222}
    esecutore = comando.crea_esecutore(conn, {"APOCALYPSE_SUDO_PASSWORD": SUDO_PASSWORD})
    ssh = esecutore._executor
    assert isinstance(ssh, SSHExecutor) and ssh.sudo_password == SUDO_PASSWORD
    assert SUDO_PASSWORD not in " ".join(ssh.base)
    assert "StrictHostKeyChecking=yes" in ssh.base and "2222" in ssh.base
    with pytest.raises(comando.ErroreParametri):
        comando.crea_esecutore({**conn, "host": "-oProxyCommand=id"}, {})


# ------------------------------------------------------------------ attack --inspect

def test_attack_inspect_un_solo_report_con_esterno_e_interno(ambiente):
    codice = web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd",
                              "--inspect", *OPZIONI_SSH, "--format", "md,json",
                              "--output", "unico"])
    assert codice == 0
    modello = json.loads((ambiente / "json" / "unico.json").read_text(encoding="utf-8"))
    fonti = {f["fonte"] for f in modello["findings"]}
    assert fonti == {"esterno", "interno"}
    assert modello["meta"]["interno"]["voci"]["database"]["stato"] == "eseguito"
    assert modello["meta"]["autorizzazione_interna"]["utente"] == "auditor"
    assert "Analisi interna" in modello["meta"]["mode"]
    interni = [f for f in modello["findings"] if f["fonte"] == "interno"]
    esterni = [f for f in modello["findings"] if f["fonte"] == "esterno"]
    assert all(f["host"] == "192.0.2.10" for f in interni)
    assert all(f["host"] == "esempio.it" for f in esterni)
    assert len({f["id"] for f in modello["findings"]}) == len(modello["findings"])
    md = (ambiente / "md" / "unico.md").read_text(encoding="utf-8")
    assert "Ricognizione passiva" in md and "## Analisi interna" in md
    assert "**Analisi interna:** 192.0.2.10 come `auditor`" in md


def test_attack_opzioni_interne_senza_inspect_rifiutate(ambiente):
    with pytest.raises(SystemExit) as e:
        web_report.main([URL, "--env", "test", "--yes", "--no-banner", *OPZIONI_SSH])
    assert e.value.code == 2


def test_attack_senza_inspect_non_tocca_la_macchina(ambiente, macchine):
    web_report.main([URL, "--env", "test", "--yes", "--no-banner", "--no-nvd", "--output", "solo_web"])
    assert macchine == []
    md = (ambiente / "md" / "solo_web.md").read_text(encoding="utf-8")
    assert "## Analisi interna" not in md
