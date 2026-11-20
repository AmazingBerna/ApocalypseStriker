"""Macchina FINTA per i test dell'analisi interna: output registrati, nessuna connessione.

Simula un Ubuntu con nginx, MySQL e un'app Python. Risponde ai comandi con output
realistici e registra ogni chiamata (argomenti, stdin, sudo), così i test possono
controllare che passino solo comandi ammessi e che le credenziali non finiscano mai
negli argomenti.
"""
import json
import subprocess

from apocalypsescan_app.interno import database

DB_PASSWORD = "DbPw-Segreta-42"
SUDO_PASSWORD = "Sudo-Segreta-7"
SEGRETO_NEL_CODICE = "SuperSegreta!99"
ENV = {"APOCALYPSE_DB_USER": "audit_ro", "APOCALYPSE_DB_PASSWORD": DB_PASSWORD,
       "APOCALYPSE_SUDO_PASSWORD": SUDO_PASSWORD}

# ------------------------------------------------------------------ output registrati

PS = """root 1 systemd
root 812 python3
www-data 900 nginx
mysql 700 mysqld
"""
SS = """LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=900,fd=6),("nginx",pid=901,fd=6))
LISTEN 0 151 0.0.0.0:3306 0.0.0.0:* users:(("mysqld",pid=700,fd=23))
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=14))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=600,fd=4))
LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:(("python3",pid=812,fd=5))
"""
SYSTEMCTL = """nginx.service loaded active running A high performance web server
mysql.service loaded active running MySQL Community Server
vsftpd.service loaded active running vsftpd FTP server
ssh.service loaded active running OpenBSD Secure Shell server
"""
EXE = {"/proc/900/exe": "/usr/sbin/nginx", "/proc/700/exe": "/usr/sbin/mysqld",
       "/proc/600/exe": "/usr/sbin/sshd", "/proc/812/exe": "/usr/bin/python3.10",
       "/proc/500/exe": "/usr/lib/systemd/systemd-resolved"}
DPKG_S = {"/usr/sbin/nginx": "nginx-core", "/usr/sbin/mysqld": "mysql-server-core-8.0",
          "/usr/sbin/sshd": "openssh-server", "/usr/bin/python3.10": "python3.10-minimal",
          "/usr/lib/systemd/systemd-resolved": "systemd"}
VERSIONI = {"nginx-core": "1.18.0-6ubuntu14.4", "mysql-server-core-8.0": "8.0.36-0ubuntu0.22.04.1",
            "openssh-server": "1:8.9p1-3ubuntu0.6", "python3.10-minimal": "3.10.12-1~22.04.3",
            "systemd": "249.11-0ubuntu3.12", "openssl": "3.0.2-0ubuntu1.15",
            "mysql-server": "8.0.36-0ubuntu0.22.04.1"}
MYSQL = {
    "utenti": ("root\tlocalhost\tNO\tauth_socket\n"
               "app\t%\tSI\tcaching_sha2_password\n"
               "backup\tlocalhost\tNO\tmysql_native_password\n"
               "debian-sys-maint\tlocalhost\tSI\tcaching_sha2_password\n"),
    "privilegi": ("'root'@'localhost'\tSUPER\tYES\n"
                  "'app'@'%'\tSELECT\tNO\n'app'@'%'\tINSERT\tNO\n'app'@'%'\tFILE\tNO\n"
                  "'app'@'%'\tSUPER\tYES\n"
                  "'lettore'@'localhost'\tUSAGE\tNO\n"),
    "variabili": ("bind_address\t0.0.0.0\nhave_ssl\tDISABLED\nlocal_infile\tON\n"
                  "require_secure_transport\tOFF\nskip_networking\tOFF\nversion\t8.0.36\n"),
}
BANDIT = json.dumps({"results": [
    {"test_id": "B105", "test_name": "hardcoded_password_string", "issue_severity": "LOW",
     "issue_confidence": "MEDIUM", "issue_text": f"Possible hardcoded password: '{SEGRETO_NEL_CODICE}'",
     "filename": "/var/www/app/settings.py", "line_number": 12,
     "code": f"12 DB_PASSWORD = '{SEGRETO_NEL_CODICE}'\n"},
    {"test_id": "B608", "test_name": "hardcoded_sql_expressions", "issue_severity": "MEDIUM",
     "issue_confidence": "MEDIUM",
     "issue_text": "Possible SQL injection vector through string-based query construction.",
     "filename": "/var/www/app/views.py", "line_number": 40,
     "code": "40 cur.execute(\"SELECT * FROM utenti WHERE id = '%s'\" % uid)\n"},
    {"test_id": "B608", "test_name": "hardcoded_sql_expressions", "issue_severity": "MEDIUM",
     "issue_confidence": "LOW", "issue_text": "Possible SQL injection vector.",
     "filename": "/var/www/app/api.py", "line_number": 7, "code": "7 ...\n"},
]})
NGINX_T = """nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/nginx.conf:
http {
    # server_tokens off;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    server {
        listen 80;
        add_header X-Frame-Options SAMEORIGIN;
    }
}
"""
FIND = "/var/www/app/.env\n/var/www/app/backup.sql\n"
STAT = {"/var/www/app/.env": "644|www-data|www-data|/var/www/app/.env",
        "/var/www/app/backup.sql": "600|www-data|www-data|/var/www/app/backup.sql",
        "/etc/mysql/debian.cnf": "600|root|root|/etc/mysql/debian.cnf",
        "/var/log/nginx": "755|root|adm|/var/log/nginx"}

PROGRAMMI = {"ps", "ss", "systemctl", "dpkg-query", "readlink", "mysql", "bandit", "nginx",
             "find", "stat", "grep"}


def _cp(rc=0, out="", err=""):
    return rc, out, err


class MacchinaFinta:
    """Executor finto: risponde con gli output registrati e registra ogni chiamata."""
    remote = True
    label = "srv-prova (via SSH)"

    def __init__(self, programmi=PROGRAMMI, sudo_ok=True, connessione=True, variazioni=None):
        self.programmi = set(programmi)
        self.sudo_ok = sudo_ok
        self.connessione = connessione
        self.variazioni = variazioni or {}
        self.chiamate = []          # (args, input, sudo, sudo_user)
        self.sudo_enabled = True

    def check_connection(self):
        return (True, "") if self.connessione else (False, "Host key verification failed.")

    def check_sudo(self):
        self.sudo_enabled = self.sudo_ok
        return self.sudo_ok

    def which(self, nome):
        return f"/usr/bin/{nome}" if nome in self.programmi else None

    def run(self, args, input=None, sudo=False, timeout=None, sudo_user=None):
        self.chiamate.append((list(args), input, sudo, sudo_user))
        rc, out, err = self._rispondi(list(args), input, sudo)
        return subprocess.CompletedProcess(args, rc, out, err)

    def _rispondi(self, a, input, sudo):
        if a[:2] == ["sh", "-c"] and a[2].startswith("command -v "):
            nome = a[2].split()[-1]
            return _cp(0, f"/usr/bin/{nome}\n") if nome in self.programmi else _cp(1)
        if a[0] in self.variazioni:
            risposta = self.variazioni[a[0]](a, input, sudo)
            if risposta is not None:
                return risposta
        if sudo and not self.sudo_ok and a[0] in ("ss", "nginx", "readlink", "find", "stat", "grep"):
            return _cp(1, "", "sudo: a password is required")
        if a[0] == "ps":
            return _cp(0, PS)
        if a[0] == "ss":
            return _cp(0, SS)
        if a[0] == "systemctl":
            return _cp(0, SYSTEMCTL)
        if a[0] == "readlink":
            return _cp(0, EXE[a[2]] + "\n")
        if a[:2] == ["dpkg-query", "-S"]:
            return _cp(0, f"{DPKG_S[a[2]]}: {a[2]}\n")
        if a[:2] == ["dpkg-query", "-W"]:
            righe = [f"{n}\t{VERSIONI[n]}" for n in a[4:] if n in VERSIONI]
            return _cp(0 if len(righe) == len(a[4:]) else 1, "\n".join(righe) + "\n",
                       "dpkg-query: no packages found matching x")
        if a[0] == "mysql":
            for nome, query in database.QUERY_MYSQL.items():
                if a[-1] == query:
                    return _cp(0, MYSQL[nome])
        if a[0] == "bandit":
            return _cp(1, BANDIT)
        if a[:2] == ["nginx", "-v"]:
            return _cp(0, "", "nginx version: nginx/1.18.0 (Ubuntu)\n")
        if a[:2] == ["nginx", "-T"]:
            return _cp(0, NGINX_T)
        if a[0] == "find":
            return _cp(0, FIND)
        if a[0] == "stat":
            righe = [STAT[p] for p in a[3:] if p in STAT]
            return _cp(0 if len(righe) == len(a[3:]) else 1, "\n".join(righe) + "\n",
                       "stat: cannot statx")
        return _cp(127, "", f"{a[0]}: comando non registrato nella macchina finta")
