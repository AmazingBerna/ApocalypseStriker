"""remote.py - Esecuzione dei comandi sulla macchina analizzata: in locale oppure via SSH.

Questi executor eseguono QUALUNQUE comando ricevano: l'analisi interna (inspect) non li usa
mai direttamente, ma solo attraverso interno.comandi.EsecutoreSolaLettura, che controlla
ogni comando con l'elenco ammesso prima di passarlo qui.

Sicurezza della connessione SSH:
- autenticazione solo a chiave (BatchMode=yes: nessuna richiesta di password a terminale);
- verifica NORMALE dell'host (StrictHostKeyChecking=yes): l'host deve essere già in
  known_hosts. Se non c'è, la connessione fallisce con un messaggio che spiega come
  verificarne l'impronta a mano. Non si accettano mai chiavi sconosciute in automatico;
- la chiave privata non viene mai letta né stampata: se ne passa solo il percorso a ssh;
- la password di sudo (se serve) viaggia su stdin, mai sulla riga di comando.
"""

import ipaddress
import re
import shlex
import shutil
import socket
import subprocess

# host, utente: niente spazi né caratteri di shell, e mai un '-' iniziale, che ssh
# leggerebbe come un'opzione (es. un host "-oProxyCommand=..." eseguirebbe un comando)
_HOST_VALIDO = re.compile(r"^[A-Za-z0-9_.:\[\]][A-Za-z0-9_.:\[\]-]*$")
_UTENTE_VALIDO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
# utenti per cui si può usare "sudo -u" (oggi solo postgres, per l'autenticazione peer)
SUDO_UTENTI_AMMESSI = ("postgres",)


def _run(cmd, input=None, timeout=None):
    """subprocess.run con I/O binario: evita che su Windows i fine riga dello stdin diventino CRLF."""
    result = subprocess.run(cmd, input=input.encode("utf-8") if input is not None else None,
                            capture_output=True, timeout=timeout)
    return subprocess.CompletedProcess(cmd, result.returncode,
                                       result.stdout.decode("utf-8", errors="replace"),
                                       result.stderr.decode("utf-8", errors="replace"))


class LocalExecutor:
    """Esegue i comandi sulla macchina da cui è lanciato ApocalypseScan."""

    remote = False

    def __init__(self):
        self.label = f"macchina locale ({socket.gethostname()})"

    def run(self, args, input=None, sudo=False, timeout=None, sudo_user=None):
        # in locale i privilegi sono quelli con cui è stato avviato il programma; il
        # cambio di utente (sudo -u) non si fa: la voce che lo richiede risulterà non
        # disponibile e l'analisi continua
        if sudo_user is not None:
            return subprocess.CompletedProcess(
                args, 1, "", f"cambio di utente ({sudo_user}) non eseguito in locale")
        return _run(args, input=input, timeout=timeout)

    def which(self, name):
        return shutil.which(name)


class SSHExecutor:
    """Esegue i comandi sul target tramite il client ssh di sistema (autenticazione a chiave)."""

    remote = True

    def __init__(self, host, user, port=22, key=None, sudo_password=None):
        if not _HOST_VALIDO.match(str(host)):
            raise ValueError(f"host non valido: {host!r}")
        if not _UTENTE_VALIDO.match(str(user)):
            raise ValueError(f"utente non valido: {user!r}")
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError(f"porta non valida: {port}")
        self.host = host
        self.user = user
        self.label = f"{host} (via SSH)"
        self.sudo_password = sudo_password
        self.sudo_enabled = user != "root"
        self.base = [
            "ssh", "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            # verifica normale: l'host deve essere già in known_hosts (mai "no" né "accept-new")
            "-o", "StrictHostKeyChecking=yes",
        ]
        if key:
            # IdentitiesOnly: usa solo la chiave indicata, non tutte quelle dell'agent
            self.base += ["-i", str(key), "-o", "IdentitiesOnly=yes"]
        self.base.append(f"{user}@{host}")

    def run(self, args, input=None, sudo=False, timeout=None, sudo_user=None):
        """Esegue args sulla macchina remota. sudo=True lo esegue come root; sudo_user lo
        esegue come quell'utente (solo SUDO_UTENTI_AMMESSI, es. postgres)."""
        if sudo_user is not None and sudo_user not in SUDO_UTENTI_AMMESSI:
            raise ValueError(f"sudo -u {sudo_user!r} non ammesso")
        command = shlex.join(args)
        if (sudo and self.sudo_enabled) or sudo_user is not None:
            opzioni = f"-u {sudo_user} " if sudo_user else ""
            if self.sudo_password:
                command = f"sudo -S -p '' {opzioni}" + command
                input = self.sudo_password + "\n" + (input or "")
            else:
                command = f"sudo -n {opzioni}" + command
        return _run(self.base + [command], input=input, timeout=timeout)

    def which(self, name):
        result = self.run(["sh", "-c", f"command -v {shlex.quote(name)}"], timeout=30)
        path = result.stdout.strip()
        return path if result.returncode == 0 and path else None

    def check_connection(self):
        """Restituisce (ok, messaggio di errore spiegato)."""
        try:
            result = self.run(["true"], timeout=30)
        except subprocess.TimeoutExpired:
            return False, "timeout della connessione"
        if result.returncode == 0:
            return True, ""
        return False, spiega_errore_ssh(result.stderr, self.user, self.host)

    def check_sudo(self):
        """True se i comandi con sudo funzionano; altrimenti li esegue senza privilegi."""
        if not self.sudo_enabled:
            return True
        try:
            ok = self.run(["true"], sudo=True, timeout=30).returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        if not ok:
            self.sudo_enabled = False
        return ok


def spiega_errore_ssh(stderr, user="utente", host="host"):
    """Traduce gli errori più comuni di ssh in un messaggio che dice cosa fare.
    Non contiene mai la chiave privata: ssh non la stampa e qui non viene letta."""
    testo = (stderr or "").strip()
    basso = testo.lower()
    if "remote host identification has changed" in basso:
        return ("la chiave dell'host è CAMBIATA rispetto a known_hosts: potrebbe essere stato "
                "reinstallato, ma anche un attacco man-in-the-middle. Verifica l'impronta con "
                "l'amministratore prima di aggiornare known_hosts (ssh-keygen -R " f"{host}).")
    if ("host key verification failed" in basso
            or "no ecdsa host key is known" in basso or "host key is known" in basso):
        return (f"l'host {host} non è in known_hosts. Collegati una volta a mano con "
                f"'ssh {user}@{host}', confronta l'impronta mostrata con quella fornita "
                "dall'amministratore e rispondi 'yes' solo se coincide; poi rilancia.")
    if "permission denied" in basso:
        return ("accesso negato: controlla utente e chiave (--key o APOCALYPSE_SSH_KEY) e che "
                "la chiave pubblica sia in ~/.ssh/authorized_keys sulla macchina analizzata.")
    if "could not resolve hostname" in basso:
        return f"nome host non risolto: {host}"
    if "connection refused" in basso:
        return "connessione rifiutata: il servizio SSH non è attivo o la porta è errata."
    if "timed out" in basso:
        return "timeout della connessione: host irraggiungibile o porta filtrata."
    return testo or "errore di connessione SSH sconosciuto"


def is_single_host(target):
    try:
        return ipaddress.ip_network(target, strict=False).num_addresses == 1
    except ValueError:
        return True   # hostname


def is_local_address(target):
    """True se il target è un indirizzo della macchina locale."""
    if not is_single_host(target):
        return False
    try:
        ip = socket.gethostbyname(target.split("/")[0])
    except OSError:
        return False
    if ip.startswith("127."):
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((ip, 0))   # riesce solo se l'indirizzo appartiene a questa macchina
        return True
    except OSError:
        return False
