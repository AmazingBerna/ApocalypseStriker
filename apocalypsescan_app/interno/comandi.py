"""comandi.py - ELENCO AMMESSO dei comandi dell'analisi interna, e l'unico esecutore che la usa.

Regola: inspect è in SOLA LETTURA. Sulla macchina analizzata si possono eseguire soltanto i
comandi descritti qui sotto, come MODELLI fissi: programma e opzioni sono scritti nel codice,
e solo alcune posizioni accettano un valore variabile (un percorso, un PID, il nome di un
pacchetto), controllato da un "segnaposto". Tutto il resto viene rifiutato con
ComandoNonAmmesso PRIMA di arrivare alla macchina.

Le query SQL sono stringhe fisse (QUERY_MYSQL, QUERY_POSTGRES) e possono essere solo
SELECT o SHOW. Le credenziali del database non compaiono mai negli argomenti: arrivano al
client su stdin (vedi SCRIPT_PSQL e il modello di mysql con --defaults-extra-file=/dev/stdin).

EsecutoreSolaLettura avvolge un executor di remote.py (SSHExecutor o LocalExecutor) ed è
l'UNICO oggetto che l'analisi interna riceve: chiama verifica() prima di ogni comando.
"""
import re

# ==========================================================================
# Segnaposto: le posizioni variabili di un modello
# ==========================================================================


class Segnaposto:
    """Posizione variabile di un modello: accetta() dice se il valore è ammesso."""
    descrizione = "valore"

    def accetta(self, valore):
        raise NotImplementedError


class Percorso(Segnaposto):
    """Percorso assoluto senza '..', senza caratteri strani e senza '-' iniziale."""
    descrizione = "percorso assoluto"
    _AMMESSO = re.compile(r"^/[A-Za-z0-9_./@+,=-]*$")

    def accetta(self, valore):
        return (bool(self._AMMESSO.match(valore))
                and ".." not in valore.split("/")
                and len(valore) <= 4096)


class Regex(Segnaposto):
    """Valore che corrisponde per intero all'espressione regolare."""

    def __init__(self, espressione, descrizione):
        self._re = re.compile(espressione)
        self.descrizione = descrizione

    def accetta(self, valore):
        return bool(self._re.fullmatch(valore))


class Scelta(Segnaposto):
    """Valore preso da un insieme fisso (es. le query SQL ammesse)."""

    def __init__(self, valori, descrizione):
        self.valori = frozenset(valori)
        self.descrizione = descrizione

    def accetta(self, valore):
        return valore in self.valori


class Ripeti:
    """Ultimo elemento di un modello: da 1 a massimo valori, ognuno accettato dal segnaposto."""

    def __init__(self, segnaposto, massimo=200):
        self.segnaposto = segnaposto
        self.massimo = massimo


PERCORSO = Percorso()
PID = Regex(r"[0-9]{1,9}", "PID")
PROC_EXE = Regex(r"/proc/[0-9]{1,9}/exe", "eseguibile di un processo (/proc/PID/exe)")
PACCHETTO = Regex(r"[a-z0-9][a-z0-9+.:~_-]{0,127}", "nome di pacchetto")

# ==========================================================================
# Query SQL ammesse: stringhe fisse, solo SELECT o SHOW
# ==========================================================================

QUERY_MYSQL = {
    # utente, host, password vuota (SI/NO: l'hash NON esce dal database), plugin di autenticazione
    "utenti": ("SELECT user, host, "
               "IF(authentication_string IS NULL OR authentication_string = '', 'NO', 'SI'), "
               "plugin FROM mysql.user"),
    "privilegi": ("SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE "
                  "FROM information_schema.USER_PRIVILEGES"),
    "variabili": ("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('bind_address', "
                  "'skip_networking', 'have_ssl', 'require_secure_transport', 'local_infile', "
                  "'version')"),
}

QUERY_POSTGRES = {
    "ruoli": ("SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, "
              "rolbypassrls FROM pg_roles"),
    "impostazioni": ("SELECT name, setting FROM pg_settings WHERE name IN "
                     "('listen_addresses', 'ssl', 'password_encryption', 'server_version')"),
    "hba": ("SELECT type, database, user_name, address, auth_method "
            "FROM pg_hba_file_rules"),
}

# Script fisso per psql: legge host, porta, utente e password da stdin (una riga ciascuno),
# li esporta per libpq e lancia psql in transazioni di sola lettura. La query è $1, cioè
# l'argomento dopo il nome "apocalypse": anche lei è verificata con QUERY_POSTGRES.
SCRIPT_PSQL = (
    "IFS= read -r PGHOST; IFS= read -r PGPORT; IFS= read -r PGUSER; IFS= read -r PGPASSWORD; "
    "export PGHOST PGPORT PGUSER PGPASSWORD; "
    "PGOPTIONS='-c default_transaction_read_only=on'; export PGOPTIONS; "
    "exec psql -X -A -t -w -F '|' -v ON_ERROR_STOP=1 -d postgres -c \"$1\""
)

# Programmi di cui si può chiedere se sono installati (command -v NOME)
PROGRAMMI_NOTI = ("ss", "ps", "systemctl", "dpkg-query", "rpm", "readlink", "mysql", "psql",
                  "bandit", "semgrep", "nginx", "apachectl", "apache2ctl", "httpd", "stat", "find",
                  "grep")

# ==========================================================================
# I modelli ammessi
# ==========================================================================

QUERY_M = Scelta(QUERY_MYSQL.values(), "query MySQL ammessa")
QUERY_P = Scelta(QUERY_POSTGRES.values(), "query PostgreSQL ammessa")

# Nomi dei file "sensibili" cercati nel codice (solo nome e permessi, mai il contenuto)
NOMI_SENSIBILI = (".env", "*.pem", "*.key", "id_rsa", "id_ed25519", "*.sql", "*.bak",
                  "wp-config.php", "settings.py", "config.php", "database.yml")
_FIND_NOMI = []
for _i, _nome in enumerate(NOMI_SENSIBILI):
    _FIND_NOMI += (["-o"] if _i else []) + ["-name", _nome]

MODELLI = (
    # connessione e sudo
    ("true",),
    ("sh", "-c", Regex(r"command -v (" + "|".join(re.escape(p) for p in PROGRAMMI_NOTI) + ")",
                       "command -v di un programma noto")),
    # processi e servizi (ps senza la riga di comando: può contenere password)
    ("ps", "-eo", "user=,pid=,comm="),
    ("ss", "-H", "-tlnp"),
    ("systemctl", "list-units", "--type=service", "--state=running", "--no-pager",
     "--no-legend", "--plain"),
    ("readlink", "-f", PROC_EXE),
    # pacchetti: a chi appartiene un file, versioni di pacchetti dati
    ("dpkg-query", "-S", PERCORSO),
    ("rpm", "-qf", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n", PERCORSO),
    ("dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n", Ripeti(PACCHETTO)),
    ("rpm", "-q", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n", Ripeti(PACCHETTO)),
    # database: credenziali su stdin, query fisse
    ("mysql", "--defaults-extra-file=/dev/stdin", "--batch", "--skip-column-names",
     "--connect-timeout=10", "-e", QUERY_M),
    ("mysql", "--batch", "--skip-column-names", "--connect-timeout=10", "-e", QUERY_M),
    ("sh", "-c", SCRIPT_PSQL, "apocalypse", QUERY_P),
    ("psql", "-X", "-A", "-t", "-w", "-F", "|", "-d", "postgres", "-c", QUERY_P),
    # analisi statica del codice (non modificano nulla; Semgrep solo con regole locali)
    ("bandit", "-r", PERCORSO, "-f", "json", "-q"),
    ("semgrep", "scan", "--config", PERCORSO, "--metrics=off", "--disable-version-check",
     "--json", "--quiet", PERCORSO),
    # web server: configurazione (letta e filtrata, mai salvata intera) e versioni
    ("nginx", "-T"),
    ("nginx", "-v"),
    ("apachectl", "-v"),
    ("apache2ctl", "-v"),
    ("httpd", "-v"),
    ("grep", "-rhiE", r"^\s*(ServerTokens|ServerSignature|SSLProtocol|Header|TraceEnable)\b",
     Ripeti(Scelta(("/etc/apache2", "/etc/httpd"), "cartella di configurazione di Apache"), 2)),
    # file sensibili e permessi: solo nomi e permessi, mai il contenuto
    ("find", PERCORSO, "-xdev", "-maxdepth", "6", "-type", "f", "(", *_FIND_NOMI, ")", "-print"),
    ("stat", "-c", "%a|%U|%G|%n", Ripeti(PERCORSO)),
)

# Utenti ammessi per sudo -u, e solo con questi programmi
SUDO_UTENTE_PROGRAMMI = {"postgres": ("psql",)}


class ComandoNonAmmesso(Exception):
    """Il comando non è nell'elenco ammesso: non viene eseguito."""


def _corrisponde(modello, args):
    for i, pezzo in enumerate(modello):
        if isinstance(pezzo, Ripeti):
            resto = args[i:]
            return (1 <= len(resto) <= pezzo.massimo
                    and all(pezzo.segnaposto.accetta(v) for v in resto))
        if i >= len(args):
            return False
        valore = args[i]
        if isinstance(pezzo, Segnaposto):
            if not pezzo.accetta(valore):
                return False
        elif valore != pezzo:
            return False
    return len(args) == len(modello)


def ammesso(args, sudo_user=None):
    """True se il comando corrisponde a uno dei modelli ammessi."""
    if not isinstance(args, (list, tuple)) or not args:
        return False
    if not all(isinstance(a, str) and "\x00" not in a and "\n" not in a for a in args):
        return False
    if sudo_user is not None and args[0] not in SUDO_UTENTE_PROGRAMMI.get(sudo_user, ()):
        return False
    return any(_corrisponde(m, list(args)) for m in MODELLI)


def verifica(args, sudo_user=None):
    """Solleva ComandoNonAmmesso se il comando non è nell'elenco ammesso.
    Il messaggio riporta solo il nome del programma: gli argomenti potrebbero contenere
    dati che non devono finire in log o terminale."""
    if not ammesso(args, sudo_user):
        nome = args[0] if isinstance(args, (list, tuple)) and args else "?"
        raise ComandoNonAmmesso(f"comando non ammesso dall'elenco di sola lettura: {nome!s:.40}")


class EsecutoreSolaLettura:
    """Unico executor che l'analisi interna riceve: controlla ogni comando con verifica().

    Registra in `eseguiti` i comandi lanciati (solo gli argomenti, MAI lo stdin, dove
    viaggiano le credenziali), per la portata del report e per i test."""

    def __init__(self, executor):
        self._executor = executor
        self.eseguiti = []

    @property
    def label(self):
        return self._executor.label

    @property
    def remote(self):
        return self._executor.remote

    @property
    def sudo_enabled(self):
        return getattr(self._executor, "sudo_enabled", False)

    def run(self, args, input=None, sudo=False, timeout=60, sudo_user=None):
        verifica(args, sudo_user)
        self.eseguiti.append(tuple(args))
        if sudo_user is not None:
            return self._executor.run(list(args), input=input, timeout=timeout,
                                      sudo_user=sudo_user)
        return self._executor.run(list(args), input=input, sudo=sudo, timeout=timeout)

    def which(self, nome):
        """Percorso del programma sulla macchina analizzata, o None se manca."""
        if nome not in PROGRAMMI_NOTI:
            raise ComandoNonAmmesso(f"programma non previsto: {nome!s:.40}")
        if not self.remote:
            return self._executor.which(nome)
        risultato = self.run(["sh", "-c", f"command -v {nome}"], timeout=30)
        percorso = risultato.stdout.strip()
        return percorso if risultato.returncode == 0 and percorso else None

    def check_connection(self):
        """(ok, motivo). In locale la connessione c'è sempre."""
        verifica(["true"])
        if hasattr(self._executor, "check_connection"):
            return self._executor.check_connection()
        return True, ""

    def check_sudo(self):
        """True se sudo funziona; altrimenti l'executor prosegue senza privilegi."""
        verifica(["true"])
        if hasattr(self._executor, "check_sudo"):
            return self._executor.check_sudo()
        return False
