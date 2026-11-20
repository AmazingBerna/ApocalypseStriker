"""database.py - Configurazione e permessi del database (MySQL/MariaDB e PostgreSQL).

Solo query fisse di lettura (comandi.QUERY_MYSQL / QUERY_POSTGRES: SELECT o SHOW).

Credenziali: SOLO da variabili d'ambiente (APOCALYPSE_DB_USER, APOCALYPSE_DB_PASSWORD,
APOCALYPSE_DB_HOST, APOCALYPSE_DB_PORT), mai dalla riga di comando. Arrivano al client
del database su stdin:
- MySQL: un file di opzioni [client] letto da --defaults-extra-file=/dev/stdin;
- PostgreSQL: lo script fisso comandi.SCRIPT_PSQL le legge da stdin e le esporta per libpq.
Senza credenziali si prova l'accesso "di sistema", senza password: per MySQL/MariaDB
`sudo mysql` (plugin unix_socket di root), per PostgreSQL psql come utente postgres
(autenticazione peer). Se nessuna delle due strade funziona, la voce è "non disponibile".

Si consiglia un utente di database IN SOLA LETTURA dedicato all'audit (vedi README).
"""
import os

from ..config import (INT_DB_HBA_PASSWORD, INT_DB_HBA_TRUST, INT_DB_IN_RETE, INT_DB_LOCAL_INFILE,
                      INT_DB_MD5, INT_DB_PRIVILEGI_LARGHI, INT_DB_PRIVILEGI_PERICOLOSI,
                      INT_DB_PRIVILEGI_SOGLIA, INT_DB_ROOT_REMOTO, INT_DB_SENZA_PASSWORD,
                      INT_DB_SENZA_SSL, INT_DB_SUPERUSER, INT_DB_UTENTE_ANONIMO,
                      INT_DB_UTENTI_SISTEMA, INT_ENV_DB_HOST, INT_ENV_DB_PASSWORD,
                      INT_ENV_DB_PORT, INT_ENV_DB_USER)
from .comandi import QUERY_MYSQL, QUERY_POSTGRES, SCRIPT_PSQL
from .comune import (ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, finding_interno, prima_riga,
                     stato)

PORTA_DEFAULT = {"mysql": "3306", "postgres": "5432"}
PROCESSI_MOTORE = {"mysql": ("mysqld", "mariadbd"), "postgres": ("postgres", "postmaster")}
_TUTTE = ("0.0.0.0", "*", "::", "")


def credenziali_da_ambiente(env=None):
    """{user, password, host, port} dalle variabili d'ambiente, o None se mancano utente o
    password. La password non viene mai stampata né registrata."""
    env = os.environ if env is None else env
    utente, password = env.get(INT_ENV_DB_USER), env.get(INT_ENV_DB_PASSWORD)
    if not utente or password is None:
        return None
    return {"user": utente, "password": password,
            "host": env.get(INT_ENV_DB_HOST) or "127.0.0.1", "port": env.get(INT_ENV_DB_PORT)}


def _riga_sicura(valore):
    """Le credenziali viaggiano una per riga: un a capo dentro un valore lo spezzerebbe."""
    if "\n" in valore or "\r" in valore:
        raise ValueError("credenziale con a capo non supportata")
    return valore


def _opzioni_mysql(cred):
    """File di opzioni [client] per --defaults-extra-file=/dev/stdin (letto su stdin)."""
    def q(v):
        return '"' + _riga_sicura(v).replace("\\", "\\\\").replace('"', '\\"') + '"'
    righe = ["[client]", f"user={q(cred['user'])}", f"password={q(cred['password'])}",
             f"host={q(cred['host'])}", f"port={int(cred['port'] or PORTA_DEFAULT['mysql'])}"]
    return "\n".join(righe) + "\n"


def _stdin_psql(cred):
    return "\n".join([_riga_sicura(cred["host"]), str(int(cred["port"] or PORTA_DEFAULT["postgres"])),
                      _riga_sicura(cred["user"]), _riga_sicura(cred["password"])]) + "\n"


# ==========================================================================
# MySQL / MariaDB
# ==========================================================================

def _query_mysql(esecutore, cred, nome):
    """(righe, errore): righe come liste di colonne (\\N = NULL diventa None)."""
    query = QUERY_MYSQL[nome]
    if cred:
        args = ["mysql", "--defaults-extra-file=/dev/stdin", "--batch", "--skip-column-names",
                "--connect-timeout=10", "-e", query]
        r, errore = esegui(esecutore, args, input=_opzioni_mysql(cred), timeout=60)
    else:
        args = ["mysql", "--batch", "--skip-column-names", "--connect-timeout=10", "-e", query]
        r, errore = esegui(esecutore, args, sudo=True, timeout=60)
    if errore:
        return None, errore
    if r.returncode != 0:
        return None, prima_riga(r.stderr) or f"mysql ha restituito {r.returncode}"
    righe = [[None if c == "\\N" else c for c in riga.split("\t")]
             for riga in r.stdout.splitlines() if riga.strip()]
    return righe, None


def _utente_grantee(grantee):
    """"'app'@'%'" -> ("app", "%")."""
    parti = grantee.split("@", 1)
    utente = parti[0].strip("'`\"")
    host = parti[1].strip("'`\"") if len(parti) > 1 else ""
    return utente, host


def _valuta_mysql_utenti(righe):
    findings = []
    for riga in righe:
        if len(riga) < 4:
            continue
        utente, host, ha_password, plugin = riga[0] or "", riga[1] or "", riga[2], (riga[3] or "")
        account = f"'{utente}'@'{host}'"
        if utente == "":
            findings.append(finding_interno(
                "database", "MySQL: utente anonimo", INT_DB_UTENTE_ANONIMO, elemento=account,
                evidence=f"mysql.user: utente vuoto, host '{host}'", key=f"mysql-anonimo-{host}"))
        if ha_password == "NO" and plugin not in ("auth_socket", "unix_socket"):
            findings.append(finding_interno(
                "database", f"MySQL: utente senza password {account}", INT_DB_SENZA_PASSWORD,
                elemento=account, evidence=f"mysql.user: authentication_string vuota, plugin {plugin}",
                key=f"mysql-nopw-{utente}-{host}"))
        if utente == "root" and host in ("%", ""):
            findings.append(finding_interno(
                "database", "MySQL: root collegabile da qualunque host", INT_DB_ROOT_REMOTO,
                elemento=account, evidence=f"mysql.user: root con host '{host}'",
                key=f"mysql-root-remoto-{host}"))
    return findings


def _valuta_mysql_privilegi(righe):
    per_account = {}
    for riga in righe:
        if len(riga) < 3:
            continue
        grantee, privilegio, concedibile = riga[0], (riga[1] or "").upper(), (riga[2] or "").upper()
        voce = per_account.setdefault(grantee, set())
        voce.add(privilegio)
        if concedibile == "YES":
            voce.add("GRANT OPTION")
    findings = []
    for grantee, privilegi in sorted(per_account.items()):
        utente, host = _utente_grantee(grantee)
        if utente in INT_DB_UTENTI_SISTEMA or privilegi <= {"USAGE"}:
            continue
        pericolosi = sorted(privilegi & set(INT_DB_PRIVILEGI_PERICOLOSI))
        if pericolosi or len(privilegi) >= INT_DB_PRIVILEGI_SOGLIA:
            esempi = ", ".join(pericolosi or sorted(privilegi)[:5])
            findings.append(finding_interno(
                "database", f"MySQL: privilegi globali troppo larghi per '{utente}'@'{host}'",
                INT_DB_PRIVILEGI_LARGHI, elemento=f"'{utente}'@'{host}'",
                evidence=f"{len(privilegi)} privilegi su *.* (tra cui {esempi})",
                key=f"mysql-priv-{utente}-{host}"))
    return findings


def _valuta_mysql_variabili(righe):
    v = {r[0].lower(): (r[1] or "") for r in righe if len(r) >= 2 and r[0]}
    findings = []
    bind = v.get("bind_address")
    in_rete = v.get("skip_networking", "OFF").upper() != "ON" and bind is not None and bind.strip() in _TUTTE
    if in_rete:
        findings.append(finding_interno(
            "database", "MySQL: in ascolto su tutte le interfacce", INT_DB_IN_RETE,
            elemento="bind_address", evidence=f"bind_address = {bind or '(vuoto)'}",
            key="mysql-bind"))
    have_ssl = v.get("have_ssl", "").upper()
    obbligatorio = v.get("require_secure_transport", "OFF").upper() == "ON"
    if in_rete and (have_ssl in ("DISABLED", "NO") or not obbligatorio):
        findings.append(finding_interno(
            "database", "MySQL: connessioni di rete senza SSL obbligatorio", INT_DB_SENZA_SSL,
            elemento="have_ssl / require_secure_transport",
            evidence=f"have_ssl = {have_ssl or '?'}, require_secure_transport = "
                     f"{'ON' if obbligatorio else 'OFF'}", key="mysql-ssl"))
    if v.get("local_infile", "").upper() in ("ON", "1"):
        findings.append(finding_interno(
            "database", "MySQL: local_infile attivo", INT_DB_LOCAL_INFILE, elemento="local_infile",
            evidence="local_infile = ON", key="mysql-local-infile"))
    return findings, v.get("version")


def _analizza_mysql(esecutore, cred):
    righe, errore = _query_mysql(esecutore, cred, "utenti")
    if errore:
        modo = "con le credenziali di APOCALYPSE_DB_USER" if cred else "come root di sistema (sudo mysql)"
        return [], stato(NON_DISPONIBILE, f"MySQL: accesso non riuscito {modo}: {errore}")
    findings = _valuta_mysql_utenti(righe)
    note = []
    righe, errore = _query_mysql(esecutore, cred, "privilegi")
    if errore:
        note.append(f"privilegi non letti ({errore})")
    else:
        findings += _valuta_mysql_privilegi(righe)
    righe, errore = _query_mysql(esecutore, cred, "variabili")
    versione = None
    if errore:
        note.append(f"variabili non lette ({errore})")
    else:
        nuovi, versione = _valuta_mysql_variabili(righe)
        findings += nuovi
    testa = f"MySQL/MariaDB {versione}" if versione else "MySQL/MariaDB"
    if note:
        return findings, stato(PARZIALE, f"{testa}: " + "; ".join(note))
    return findings, stato(ESEGUITO, f"{testa}: utenti, privilegi e variabili letti")


# ==========================================================================
# PostgreSQL
# ==========================================================================

def _query_postgres(esecutore, cred, nome):
    query = QUERY_POSTGRES[nome]
    if cred:
        r, errore = esegui(esecutore, ["sh", "-c", SCRIPT_PSQL, "apocalypse", query],
                           input=_stdin_psql(cred), timeout=60)
    else:
        args = ["psql", "-X", "-A", "-t", "-w", "-F", "|", "-d", "postgres", "-c", query]
        r, errore = esegui(esecutore, args, sudo_user="postgres", timeout=60)
    if errore:
        return None, errore
    if r.returncode != 0:
        return None, prima_riga(r.stderr) or f"psql ha restituito {r.returncode}"
    return [riga.split("|") for riga in r.stdout.splitlines() if riga.strip()], None


def _valuta_pg_ruoli(righe):
    findings = []
    for riga in righe:
        if len(riga) < 6:
            continue
        nome, superuser, _, _, login, bypass = riga[:6]
        if nome == "postgres" or login != "t":
            continue
        if superuser == "t" or bypass == "t":
            attributi = ", ".join(a for a, v in (("SUPERUSER", superuser), ("BYPASSRLS", bypass)) if v == "t")
            findings.append(finding_interno(
                "database", f"PostgreSQL: ruolo con {attributi}: {nome}", INT_DB_SUPERUSER,
                elemento=f"ruolo {nome}", evidence=f"pg_roles: {nome} {attributi}, LOGIN",
                key=f"pg-super-{nome}"))
    return findings


def _valuta_pg_impostazioni(righe):
    v = {r[0]: r[1] for r in righe if len(r) >= 2}
    findings = []
    ascolto = v.get("listen_addresses", "")
    in_rete = any(a.strip() in ("*", "0.0.0.0", "::") for a in ascolto.split(","))
    if in_rete:
        findings.append(finding_interno(
            "database", "PostgreSQL: in ascolto su tutte le interfacce", INT_DB_IN_RETE,
            elemento="listen_addresses", evidence=f"listen_addresses = '{ascolto}'", key="pg-listen"))
    if in_rete and v.get("ssl", "").lower() == "off":
        findings.append(finding_interno(
            "database", "PostgreSQL: connessioni di rete senza SSL", INT_DB_SENZA_SSL,
            elemento="ssl", evidence="ssl = off", key="pg-ssl"))
    if v.get("password_encryption", "").lower() == "md5":
        findings.append(finding_interno(
            "database", "PostgreSQL: password cifrate con md5", INT_DB_MD5,
            elemento="password_encryption", evidence="password_encryption = md5", key="pg-md5"))
    return findings, v.get("server_version")


def _valuta_pg_hba(righe):
    findings = []
    for riga in righe:
        if len(riga) < 5:
            continue
        tipo, database, utenti, indirizzo, metodo = riga[:5]
        regola_txt = f"{tipo} {database} {utenti} {indirizzo or ''} {metodo}".replace("  ", " ")
        if metodo == "trust":
            regola = INT_DB_HBA_TRUST
            if tipo == "local":       # solo socket locale: serve già un accesso alla macchina
                regola = (regola[0], regola[1], 3, regola[3])
            findings.append(finding_interno(
                "database", f"PostgreSQL: accesso senza password (trust) per {tipo} {utenti}",
                regola, elemento=f"pg_hba: {tipo} {database} {utenti}",
                evidence=f"pg_hba_file_rules: {regola_txt}", key=f"pg-trust-{tipo}-{utenti}-{indirizzo}"))
        elif metodo == "password" and tipo.startswith("host"):
            findings.append(finding_interno(
                "database", f"PostgreSQL: password in chiaro per {tipo} {utenti}", INT_DB_HBA_PASSWORD,
                elemento=f"pg_hba: {tipo} {database} {utenti}",
                evidence=f"pg_hba_file_rules: {regola_txt}", key=f"pg-pwchiaro-{utenti}-{indirizzo}"))
    return findings


def _analizza_postgres(esecutore, cred):
    righe, errore = _query_postgres(esecutore, cred, "ruoli")
    if errore:
        modo = "con le credenziali di APOCALYPSE_DB_USER" if cred else "come utente postgres (peer)"
        return [], stato(NON_DISPONIBILE, f"PostgreSQL: accesso non riuscito {modo}: {errore}")
    findings = _valuta_pg_ruoli(righe)
    note = []
    righe, errore = _query_postgres(esecutore, cred, "impostazioni")
    versione = None
    if errore:
        note.append(f"impostazioni non lette ({errore})")
    else:
        nuovi, versione = _valuta_pg_impostazioni(righe)
        findings += nuovi
    righe, errore = _query_postgres(esecutore, cred, "hba")
    if errore:
        note.append(f"pg_hba non letto ({errore}; di norma serve un superuser)")
    else:
        findings += _valuta_pg_hba(righe)
    testa = f"PostgreSQL {versione}" if versione else "PostgreSQL"
    if note:
        return findings, stato(PARZIALE, f"{testa}: " + "; ".join(note))
    return findings, stato(ESEGUITO, f"{testa}: ruoli, impostazioni e pg_hba letti")


# ==========================================================================
# Orchestrazione
# ==========================================================================

def motori_presenti(esecutore, servizi):
    """Motori da analizzare: quelli di cui gira il server (dai servizi in ascolto) oppure,
    se i processi non sono visibili, quelli di cui c'è il client."""
    processi = {p for s in (servizi or {}).get("services", []) for p in s["processes"]}
    motori = [m for m, nomi in PROCESSI_MOTORE.items() if processi & set(nomi)]
    if motori or processi:
        return motori
    return [m for m, client in (("mysql", "mysql"), ("postgres", "psql")) if esecutore.which(client)]


def raccogli(esecutore, servizi=None, env=None):
    """Analisi del database. Restituisce (findings, stato)."""
    try:
        cred = credenziali_da_ambiente(env)
    except ValueError as e:
        return [], stato(NON_DISPONIBILE, str(e))
    motori = motori_presenti(esecutore, servizi)
    if not motori:
        return [], stato(NON_DISPONIBILE, "nessun database MySQL/MariaDB o PostgreSQL rilevato")

    findings, stati = [], []
    for motore in motori:
        client = "mysql" if motore == "mysql" else "psql"
        if not esecutore.which(client):
            stati.append(stato(NON_DISPONIBILE, f"client {client} non installato sulla macchina"))
            continue
        try:
            if motore == "mysql":
                nuovi, st = _analizza_mysql(esecutore, cred)
            else:
                nuovi, st = _analizza_postgres(esecutore, cred)
        except ValueError as e:      # credenziale non trasmissibile (a capo nel valore)
            nuovi, st = [], stato(NON_DISPONIBILE, str(e))
        findings += nuovi
        stati.append(st)

    esiti = {s["stato"] for s in stati}
    if esiti == {ESEGUITO}:
        complessivo = ESEGUITO
    elif esiti == {NON_DISPONIBILE}:
        complessivo = NON_DISPONIBILE
    else:
        complessivo = PARZIALE
    return findings, stato(complessivo, "; ".join(s["dettaglio"] for s in stati))
