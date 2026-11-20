"""Test dell'analisi interna con una macchina FINTA: output registrati, nessuna connessione.

La macchina finta risponde ai comandi con output realistici (Ubuntu con nginx, MySQL e
un'app Python) e registra tutto quello che riceve, così i test possono controllare che
siano passati solo comandi ammessi e che le credenziali non siano mai finite negli argomenti.
"""
import json
import logging

import pytest

from apocalypsescan_app.interno import analisi, database, webserver
from apocalypsescan_app.interno.analisi import analisi_interna
from apocalypsescan_app.interno.comandi import EsecutoreSolaLettura, ammesso
from apocalypsescan_app.interno.pacchetti import versione_upstream
from apocalypsescan_app.interno.riservatezza import oscura
from apocalypsescan_app.servizi_locali import parse_ss

from macchina_finta import (DB_PASSWORD, ENV, PROGRAMMI, SEGRETO_NEL_CODICE, SS,
                            SUDO_PASSWORD, MacchinaFinta, _cp)


def _esegui(macchina=None, **opzioni):
    macchina = macchina or MacchinaFinta()
    esecutore = EsecutoreSolaLettura(macchina)
    opzioni.setdefault("codice", "/var/www/app")
    opzioni.setdefault("env", ENV)
    findings, meta = analisi_interna(esecutore, **opzioni)
    return findings, meta, macchina


def _items(findings):
    return [f["item"] for f in findings]


# ------------------------------------------------------------------ processi e servizi

def test_parse_ss_porte_processi_e_interfacce():
    servizi = {s["port"]: s for s in parse_ss(SS)}
    assert servizi[80]["processes"] == ["nginx"] and servizi[80]["pids"] == [900, 901]
    assert servizi[3306]["all_interfaces"] and not servizi[3306]["loopback_only"]
    assert servizi[53]["loopback_only"] and servizi[53]["addresses"] == ["127.0.0.53"]
    assert servizi[22]["addresses"] == ["::"] and servizi[22]["all_interfaces"]


def test_processi_servizi_e_porte():
    findings, meta, _ = _esegui()
    items = _items(findings)
    assert "Database in ascolto su tutte le interfacce: mysqld (3306/tcp)" in items
    assert "Processo dell'applicazione come root: python3" in items
    assert "Servizio superfluo attivo: vsftpd" in items
    porte = next(f for f in findings if f["item"].startswith("Porte TCP in ascolto"))
    assert "80/tcp nginx [nginx-core 1.18.0-6ubuntu14.4]" in porte["reason"]
    assert "8000/tcp python3" in porte["reason"] and "solo localhost" in porte["reason"]
    assert meta["voci"]["processi"]["stato"] == "eseguito"
    assert all(f["fonte"] == "interno" for f in findings)


# ------------------------------------------------------------------ database

def test_database_utente_troppo_privilegiato_e_senza_password():
    findings, meta, macchina = _esegui()
    items = _items(findings)
    assert "MySQL: privilegi globali troppo larghi per 'app'@'%'" in items
    assert "MySQL: utente senza password 'backup'@'localhost'" in items
    assert not any("root" in i and "senza password" in i for i in items)   # auth_socket è ok
    assert not any("lettore" in i for i in items)                           # solo USAGE
    assert not any("debian-sys-maint" in i for i in items)                  # utente di sistema
    assert "MySQL: in ascolto su tutte le interfacce" in items
    assert "MySQL: connessioni di rete senza SSL obbligatorio" in items
    assert "MySQL: local_infile attivo" in items
    assert meta["voci"]["database"]["stato"] == "eseguito"
    larghi = next(f for f in findings if "troppo larghi" in f["item"])
    assert larghi["impact"] * larghi["probability"] == larghi["score"]
    assert "FILE" in larghi["evidence"] and "SUPER" in larghi["evidence"]


def test_credenziali_db_su_stdin_e_mai_negli_argomenti():
    _, _, macchina = _esegui()
    chiamate_mysql = [c for c in macchina.chiamate if c[0][0] == "mysql"]
    assert chiamate_mysql
    for args, input, _, _ in chiamate_mysql:
        assert args[1] == "--defaults-extra-file=/dev/stdin"
        assert DB_PASSWORD in input and "audit_ro" in input
        assert not any(DB_PASSWORD in a or "audit_ro" in a for a in args)


def test_database_senza_credenziali_usa_sudo_mysql():
    _, meta, macchina = _esegui(env={})
    chiamate = [c for c in macchina.chiamate if c[0][0] == "mysql"]
    assert chiamate and all(sudo and input is None for _, input, sudo, _ in chiamate)
    assert "--defaults-extra-file=/dev/stdin" not in chiamate[0][0]


def test_postgres_query_e_valutazione():
    ruoli = [["app", "t", "f", "f", "t", "f"], ["postgres", "t", "t", "t", "t", "t"],
             ["lettore", "f", "f", "f", "t", "f"]]
    assert [f["item"] for f in database._valuta_pg_ruoli(ruoli)] == [
        "PostgreSQL: ruolo con SUPERUSER: app"]
    imp, versione = database._valuta_pg_impostazioni(
        [["listen_addresses", "*"], ["ssl", "off"], ["password_encryption", "md5"],
         ["server_version", "14.11"]])
    assert versione == "14.11" and len(imp) == 3
    hba = database._valuta_pg_hba([["host", "{all}", "{all}", "0.0.0.0", "trust"],
                                    ["local", "{all}", "{postgres}", "", "peer"]])
    assert len(hba) == 1 and hba[0]["impact"] == 5


# ------------------------------------------------------------------ analisi statica

def test_bandit_raggruppa_per_regola_e_toglie_codice_e_valori():
    findings, meta, _ = _esegui()
    bandit = [f for f in findings if f["source"] == "bandit"]
    assert len(bandit) == 2
    segreto = next(f for f in bandit if "B105" in f["item"])
    sql = next(f for f in bandit if "B608" in f["item"])
    assert segreto["elemento"] == "/var/www/app/settings.py:12"
    assert "settings.py:12" in segreto["evidence"]
    assert "(2)" in sql["item"] and "views.py:40" in sql["evidence"] and "api.py:7" in sql["evidence"]
    testo = json.dumps(bandit)
    assert SEGRETO_NEL_CODICE not in testo
    assert "cur.execute" not in testo           # il frammento di codice non c'è mai
    assert "Bandit: 3 problemi" in meta["voci"]["codice"]["dettaglio"]


def test_file_sensibili_solo_nomi_e_permessi():
    findings, _, macchina = _esegui()
    items = _items(findings)
    assert "File sensibile leggibile da tutti: .env" in items
    assert "File sensibile nella cartella del codice: backup.sql" in items
    assert "Leggibile da tutti: /var/log/nginx" in items
    assert not any(c[0][0] in ("cat", "head", "less") for c in macchina.chiamate)


def test_semgrep_solo_con_regole_locali():
    macchina = MacchinaFinta(programmi=PROGRAMMI | {"semgrep"}, variazioni={
        "semgrep": lambda a, i, s: _cp(0, json.dumps({"results": [
            {"check_id": "python.lang.security.sql-injection", "path": "/var/www/app/db.py",
             "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "SQL injection",
                                             "lines": "cur.execute(q % 'x')"}}]}))})
    findings, _, macchina = _esegui(macchina)
    assert not any(c[0][0] == "semgrep" for c in macchina.chiamate)   # senza --semgrep-rules: no
    findings, meta, macchina = _esegui(MacchinaFinta(programmi=macchina.programmi,
                                                     variazioni=macchina.variazioni),
                                       semgrep_rules="/opt/regole")
    chiamata = next(c[0] for c in macchina.chiamate if c[0][0] == "semgrep")
    assert "--metrics=off" in chiamata and "auto" not in chiamata
    semgrep = next(f for f in findings if f["source"] == "semgrep")
    assert "cur.execute" not in json.dumps(semgrep)


# ------------------------------------------------------------------ web server e pacchetti

def test_nginx_configurazione():
    findings, meta, _ = _esegui()
    items = _items(findings)
    assert "nginx dichiara la versione (server_tokens)" in items     # solo commentato: default on
    assert "nginx abilita TLS obsoleto: TLSv1, TLSv1.1" in items
    header = next(f for f in findings if f["item"].startswith("nginx non imposta"))
    assert "x-frame-options" not in header["evidence"]
    assert "content-security-policy" in header["evidence"]
    assert meta["voci"]["webserver"]["stato"] == "eseguito"


def test_apache_protocolli_e_direttive():
    d = webserver.analizza_apache("ServerTokens OS\nSSLProtocol all -SSLv3\nTraceEnable Off\n"
                                  "Header always set Strict-Transport-Security \"max-age=1\"\n")
    items = [f["item"] for f in webserver._finding_apache(d)]
    assert "Apache dichiara la versione (ServerTokens)" in items
    assert "Apache abilita TLS obsoleto: TLSv1, TLSv1.1" in items
    assert not any("TRACE" in i for i in items)
    assert webserver._protocolli_apache(["-all +TLSv1.2 +TLSv1.3"]) == []


def test_versione_upstream_dei_pacchetti():
    assert versione_upstream("1:1.18.0-6ubuntu14.4") == "1.18.0"
    assert versione_upstream("3.0.2-0ubuntu1.15") == "3.0.2"
    assert versione_upstream("1.1.1f-1ubuntu2") == "1.1.1f"
    assert versione_upstream("2:8.1+92ubuntu1") is None      # metapacchetto: niente CPE


def test_pacchetti_e_cve_senza_nvd():
    findings, meta, _ = _esegui()
    chiave = next(f for f in findings if f["item"].startswith("Pacchetti chiave"))
    assert "nginx-core 1.18.0-6ubuntu14.4" in chiave["reason"] and "openssl" in chiave["reason"]
    assert "NVD disattivato" in meta["voci"]["pacchetti"]["dettaglio"]


def test_pacchetti_con_nvd_finto():
    def arricchisci_finto(tecnologie, attivo=True):
        for t in tecnologie:
            t["cpe"] = f"cpe:2.3:a:x:{t['prodotto']}:{t['versione']}"
            t["cve"] = [{"id": "CVE-2021-23017", "gravita": "HIGH", "punteggio": 7.7,
                         "vettore": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        return tecnologie
    from apocalypsescan_app.interno import pacchetti
    macchina = MacchinaFinta()
    servizi = {"manager": "dpkg", "services": []}
    findings, st = pacchetti.raccogli(EsecutoreSolaLettura(macchina), servizi, nvd=True,
                                      arricchisci=arricchisci_finto)
    cve = [f for f in findings if f["impact"]]
    assert cve and all(f["fonte"] == "interno" and f["probability"] <= 2 for f in cve)  # backport
    assert st["stato"] == "eseguito"


# ------------------------------------------------------------------ degrado graduale

def test_degrado_bandit_mancante():
    findings, meta, _ = _esegui(MacchinaFinta(programmi=PROGRAMMI - {"bandit"}))
    st = meta["voci"]["codice"]
    assert st["stato"] == "parziale" and "Bandit non installato" in st["dettaglio"]
    assert any(f["source"] == "database" for f in findings)      # il resto continua


def test_degrado_sudo_negato():
    findings, meta, _ = _esegui(MacchinaFinta(sudo_ok=False))
    assert meta["sudo"] is False
    assert meta["voci"]["processi"]["stato"] in ("parziale", "non disponibile")
    assert "ss non riuscito" in meta["voci"]["processi"]["dettaglio"]
    ws = meta["voci"]["webserver"]
    assert ws["stato"] == "non disponibile" and "nginx -T" in ws["dettaglio"]
    assert "Processo dell'applicazione come root: python3" in _items(findings)   # ps va senza sudo
    assert any(f["source"] == "bandit" for f in findings)
    assert "ricerca dei file sensibili non riuscita" in meta["voci"]["codice"]["dettaglio"]


def test_degrado_database_non_raggiungibile_e_password_oscurata():
    errore = (f"ERROR 2002 (HY000): Can't connect to MySQL server (password={DB_PASSWORD})")
    macchina = MacchinaFinta(variazioni={"mysql": lambda a, i, s: _cp(1, "", errore)})
    findings, meta, _ = _esegui(macchina)
    st = meta["voci"]["database"]
    assert st["stato"] == "non disponibile" and "Can't connect" in st["dettaglio"]
    assert DB_PASSWORD not in json.dumps(meta)
    assert not any(f["source"] == "database" for f in findings)
    assert any(f["source"] == "bandit" for f in findings)


def test_degrado_connessione_fallita():
    findings, meta, macchina = _esegui(MacchinaFinta(connessione=False))
    assert findings == []
    assert meta["connessione"].startswith("connessione non riuscita")
    assert all(s["stato"] == "non disponibile" for s in meta["voci"].values())
    assert macchina.chiamate == []


def test_degrado_errore_imprevisto_in_un_raccoglitore(monkeypatch):
    def esplode(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(analisi.webserver, "raccogli", esplode)
    findings, meta, _ = _esegui()
    assert meta["voci"]["webserver"] == {"stato": "non disponibile",
                                         "dettaglio": "errore imprevisto (RuntimeError)"}
    assert meta["voci"]["database"]["stato"] == "eseguito"


def test_nessun_database_rilevato():
    macchina = MacchinaFinta(programmi=PROGRAMMI - {"mysql"},
                             variazioni={"ss": lambda a, i, s: _cp(0, SS.replace("mysqld", "redis"))})
    _, meta, _ = _esegui(macchina)
    assert meta["voci"]["database"]["stato"] == "non disponibile"


# ------------------------------------------------------------------ sicurezza

def test_analisi_invoca_solo_comandi_ammessi():
    for opzioni in ({}, {"semgrep_rules": "/opt/regole"}, {"env": {}}):
        _, _, macchina = _esegui(MacchinaFinta(programmi=PROGRAMMI | {"semgrep", "psql"}), **opzioni)
        assert macchina.chiamate
        for args, _, _, sudo_user in macchina.chiamate:
            assert ammesso(args, sudo_user), args


def test_analisi_rifiuta_un_executor_senza_elenco_ammesso():
    with pytest.raises(TypeError):
        analisi_interna(MacchinaFinta())


def test_credenziali_e_segreti_mai_in_risultati_log_e_stdout(capsys, caplog):
    caplog.set_level(logging.DEBUG)
    righe = []
    findings, meta, macchina = _esegui(log=righe.append)
    print("\n".join(analisi.riepilogo_stato(meta)))
    uscita = capsys.readouterr()
    testi = [json.dumps(findings, ensure_ascii=False), json.dumps(meta, ensure_ascii=False),
             "\n".join(righe), uscita.out, uscita.err, caplog.text,
             json.dumps([c[0] for c in macchina.chiamate])]
    for testo in testi:
        for segreto in (DB_PASSWORD, SUDO_PASSWORD, SEGRETO_NEL_CODICE):
            assert segreto not in testo


def test_oscura_toglie_valori_ma_lascia_i_nomi():
    assert oscura("DB_PASSWORD=abc123 e api_key: 'k-9'") == "DB_PASSWORD=*** e api_key: '***'"
    assert oscura("senza password: chiunque entra") == "senza password: chiunque entra"
    assert oscura("errore con pw-nota", ["pw-nota"]) == "errore con ***"
    assert "PRIVATE" not in oscura("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")
