"""remote.py - Esecuzione dei comandi sulla macchina analizzata: in locale oppure via SSH."""

import ipaddress
import shlex
import shutil
import socket
import subprocess


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

    def run(self, args, input=None, sudo=False, timeout=None):
        # in locale i privilegi sono quelli con cui è stato avviato il programma
        return _run(args, input=input, timeout=timeout)

    def which(self, name):
        return shutil.which(name)


class SSHExecutor:
    """Esegue i comandi sul target tramite il client ssh di sistema (autenticazione a chiave)."""

    remote = True

    def __init__(self, host, user, port=22, key=None, sudo_password=None):
        self.host = host
        self.user = user
        self.label = f"{host} (via SSH)"
        self.sudo_password = sudo_password
        self.sudo_enabled = user != "root"
        self.base = [
            "ssh", "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
        ]
        if key:
            self.base += ["-i", key]
        self.base.append(f"{user}@{host}")

    def run(self, args, input=None, sudo=False, timeout=None):
        command = shlex.join(args)
        if sudo and self.sudo_enabled:
            if self.sudo_password:
                command = "sudo -S -p '' " + command
                input = self.sudo_password + "\n" + (input or "")
            else:
                command = "sudo -n " + command
        return _run(self.base + [command], input=input, timeout=timeout)

    def which(self, name):
        result = self.run(["sh", "-c", f"command -v {shlex.quote(name)}"], timeout=30)
        path = result.stdout.strip()
        return path if result.returncode == 0 and path else None

    def check_connection(self):
        """Restituisce (ok, messaggio di errore)."""
        try:
            result = self.run(["true"], timeout=30)
        except subprocess.TimeoutExpired:
            return False, "timeout della connessione"
        return result.returncode == 0, result.stderr.strip()

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
