"""Test dell'elenco ammesso (interno/comandi.py) e della connessione SSH (remote.py).

Nessuna connessione vera: SSHExecutor viene solo costruito e ispezionato, e gli executor
sono finti.
"""
import subprocess

import pytest

from apocalypsescan_app.interno import comandi
from apocalypsescan_app.interno.comandi import (
    QUERY_MYSQL, QUERY_POSTGRES, SCRIPT_PSQL, ComandoNonAmmesso, EsecutoreSolaLettura,
    ammesso, verifica)
from apocalypsescan_app.remote import SSHExecutor, spiega_errore_ssh


class ExecutorFinto:
    """Registra i comandi ricevuti senza eseguire nulla."""
    remote = True
    label = "finto (via SSH)"

    def __init__(self):
        self.ricevuti = []

    def run(self, args, input=None, sudo=False, timeout=None, sudo_user=None):
        self.ricevuti.append(list(args))
        return subprocess.CompletedProcess(args, 0, "/usr/bin/bandit\n", "")


# ---------------------------------------------------------------- comandi ammessi

AMMESSI = [
    ["true"],
    ["ps", "-eo", "user=,pid=,comm="],
    ["ss", "-H", "-tlnp"],
    ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager",
     "--no-legend", "--plain"],
    ["readlink", "-f", "/proc/1234/exe"],
    ["dpkg-query", "-S", "/usr/sbin/nginx"],
    ["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n", "nginx", "openssl"],
    ["mysql", "--defaults-extra-file=/dev/stdin", "--batch", "--skip-column-names",
     "--connect-timeout=10", "-e", QUERY_MYSQL["utenti"]],
    ["sh", "-c", SCRIPT_PSQL, "apocalypse", QUERY_POSTGRES["ruoli"]],
    ["bandit", "-r", "/var/www/app", "-f", "json", "-q"],
    ["semgrep", "scan", "--config", "/opt/regole/python.yml", "--metrics=off",
     "--disable-version-check", "--json", "--quiet", "/var/www/app"],
    ["nginx", "-T"],
    ["sh", "-c", "command -v bandit"],
    ["stat", "-c", "%a|%U|%G|%n", "/var/www/app/.env", "/etc/nginx/nginx.conf"],
]


@pytest.mark.parametrize("args", AMMESSI)
def test_comandi_di_lettura_ammessi(args):
    assert ammesso(args)
    verifica(args)   # non solleva


VIETATI = [
    ["rm", "-rf", "/"],
    ["systemctl", "restart", "nginx"],
    ["systemctl", "stop", "mysql"],
    ["apt-get", "install", "bandit"],
    ["pip", "install", "bandit"],
    ["dpkg", "-i", "/tmp/x.deb"],
    ["reboot"],
    ["sh", "-c", "rm -rf /tmp/x"],
    ["sh", "-c", "command -v bandit; rm -rf /"],
    ["bash", "-c", "id"],
    ["ps", "auxww"],                                    # mostrerebbe le righe di comando
    ["ss", "-H", "-tlnp", "-K"],                        # -K chiude le connessioni
    ["mysql", "--batch", "--skip-column-names", "--connect-timeout=10", "-e", "DROP DATABASE app"],
    ["mysql", "--batch", "--skip-column-names", "--connect-timeout=10", "-e",
     QUERY_MYSQL["utenti"] + "; DELETE FROM mysql.user"],
    ["psql", "-X", "-A", "-t", "-w", "-F", "|", "-d", "postgres", "-c", "ALTER ROLE x SUPERUSER"],
    ["semgrep", "scan", "--config", "auto", "--metrics=off", "--disable-version-check",
     "--json", "--quiet", "/var/www/app"],              # mai regole scaricate da internet
    ["semgrep", "scan", "--config", "/opt/r.yml", "--metrics=on", "--disable-version-check",
     "--json", "--quiet", "/var/www/app"],
    ["bandit", "-r", "/var/www/../../etc", "-f", "json", "-q"],
    ["bandit", "-r", "relativo/app", "-f", "json", "-q"],
    ["bandit", "-r", "/var/www/app;id", "-f", "json", "-q"],
    ["find", "/var/www", "-delete"],
    ["find", "/var/www", "-exec", "rm", "{}", ";"],
    ["nginx", "-s", "reload"],
    ["readlink", "-f", "/etc/shadow"],
    ["true", "extra"],
    [],
]


@pytest.mark.parametrize("args", VIETATI)
def test_comandi_non_ammessi_rifiutati(args):
    assert not ammesso(args)
    with pytest.raises(ComandoNonAmmesso):
        verifica(args)


def test_query_sql_solo_select_o_show():
    for query in [*QUERY_MYSQL.values(), *QUERY_POSTGRES.values()]:
        assert query.lstrip().upper().startswith(("SELECT ", "SHOW ")), query
        assert ";" not in query


def test_sudo_utente_solo_postgres_con_psql():
    psql = ["psql", "-X", "-A", "-t", "-w", "-F", "|", "-d", "postgres", "-c",
            QUERY_POSTGRES["ruoli"]]
    assert ammesso(psql, sudo_user="postgres")
    assert not ammesso(psql, sudo_user="root")
    assert not ammesso(["ss", "-H", "-tlnp"], sudo_user="postgres")


def test_messaggio_di_rifiuto_non_riporta_gli_argomenti():
    with pytest.raises(ComandoNonAmmesso) as e:
        verifica(["mysql", "-psegretissima", "-e", "SELECT 1"])
    assert "segretissima" not in str(e.value)


# ---------------------------------------------------------------- EsecutoreSolaLettura

def test_esecutore_rifiuta_prima_di_arrivare_alla_macchina():
    finto = ExecutorFinto()
    esecutore = EsecutoreSolaLettura(finto)
    with pytest.raises(ComandoNonAmmesso):
        esecutore.run(["systemctl", "restart", "nginx"], sudo=True)
    assert finto.ricevuti == []          # il comando non è mai partito


def test_esecutore_passa_i_comandi_ammessi_e_li_registra_senza_stdin():
    finto = ExecutorFinto()
    esecutore = EsecutoreSolaLettura(finto)
    esecutore.run(["ss", "-H", "-tlnp"], input="password-segreta\n", sudo=True)
    assert finto.ricevuti == [["ss", "-H", "-tlnp"]]
    assert esecutore.eseguiti == [("ss", "-H", "-tlnp")]
    assert "password-segreta" not in repr(esecutore.eseguiti)


def test_which_passa_dall_elenco_ammesso():
    finto = ExecutorFinto()
    esecutore = EsecutoreSolaLettura(finto)
    assert esecutore.which("bandit") == "/usr/bin/bandit"
    assert finto.ricevuti == [["sh", "-c", "command -v bandit"]]
    with pytest.raises(ComandoNonAmmesso):
        esecutore.which("rm")


def test_tutti_i_modelli_iniziano_con_un_programma_fisso():
    for modello in comandi.MODELLI:
        assert isinstance(modello[0], str)


# ---------------------------------------------------------------- SSHExecutor

def test_ssh_verifica_normale_di_known_hosts():
    ssh = SSHExecutor("192.0.2.10", "auditor", key="/home/me/.ssh/id_ed25519")
    opzioni = " ".join(ssh.base)
    assert "StrictHostKeyChecking=yes" in opzioni
    assert "StrictHostKeyChecking=no" not in opzioni
    assert "accept-new" not in opzioni
    assert "UserKnownHostsFile=/dev/null" not in opzioni
    assert "BatchMode=yes" in opzioni
    assert ssh.base[-1] == "auditor@192.0.2.10"


@pytest.mark.parametrize("host", ["-oProxyCommand=id", "host name", "a;b", ""])
def test_ssh_rifiuta_host_che_sembrano_opzioni(host):
    with pytest.raises(ValueError):
        SSHExecutor(host, "auditor")


def test_ssh_rifiuta_utente_e_porta_non_validi():
    with pytest.raises(ValueError):
        SSHExecutor("192.0.2.10", "-oX")
    with pytest.raises(ValueError):
        SSHExecutor("192.0.2.10", "auditor", port=70000)


def test_ssh_password_sudo_su_stdin_e_mai_sulla_riga_di_comando(monkeypatch):
    catturati = {}

    def finto_run(cmd, input=None, timeout=None):
        catturati["cmd"], catturati["input"] = cmd, input
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("apocalypsescan_app.remote._run", finto_run)
    ssh = SSHExecutor("192.0.2.10", "auditor", sudo_password="pw-sudo-123")
    ssh.run(["ss", "-H", "-tlnp"], sudo=True)
    assert "pw-sudo-123" not in " ".join(catturati["cmd"])
    assert catturati["input"].startswith("pw-sudo-123\n")
    assert catturati["cmd"][-1].startswith("sudo -S -p '' ")


def test_ssh_sudo_utente_solo_ammessi(monkeypatch):
    monkeypatch.setattr("apocalypsescan_app.remote._run",
                        lambda cmd, input=None, timeout=None: subprocess.CompletedProcess(cmd, 0, "", ""))
    ssh = SSHExecutor("192.0.2.10", "auditor")
    risultato = ssh.run(["psql", "-c", "SELECT 1"], sudo_user="postgres")
    assert risultato.args[-1].startswith("sudo -n -u postgres ")
    with pytest.raises(ValueError):
        ssh.run(["id"], sudo_user="root")


def test_errori_ssh_spiegati():
    assert "known_hosts" in spiega_errore_ssh("Host key verification failed.", "u", "h")
    assert "man-in-the-middle" in spiega_errore_ssh(
        "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "u", "h")
    assert "chiave" in spiega_errore_ssh("u@h: Permission denied (publickey).", "u", "h")
