"""processi.py - Processi, servizi attivi e porte in ascolto della macchina analizzata.

Tre fonti, tutte in sola lettura:
- `ps -eo user=,pid=,comm=`: utente e nome di ogni processo (MAI la riga di comando, che può
  contenere password passate come argomento);
- `systemctl list-units --type=service --state=running`: i servizi attivi;
- servizi_locali.leggi_servizi: porte in ascolto -> processo -> pacchetto.

Finding: database/cache in ascolto su tutte le interfacce, runtime dell'applicazione che
girano come root, servizi superflui attivi; più un finding informativo con le porte.
"""
import re

from ..config import (INT_APP_COME_ROOT, INT_DB_TUTTE_INTERFACCE, INT_PROCESSI_DATABASE,
                      INT_RUNTIME_APPLICAZIONE, INT_SERVIZI_SUPERFLUI)
from ..servizi_locali import leggi_servizi
from .comune import (ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, finding_interno, info_interno,
                     prima_riga, stato)


def parse_ps(testo):
    """Righe "utente pid comando" -> [{user, pid, comm}]."""
    processi = []
    for riga in (testo or "").splitlines():
        parti = riga.split(None, 2)
        if len(parti) == 3 and parti[1].isdigit():
            processi.append({"user": parti[0], "pid": int(parti[1]), "comm": parti[2].strip()})
    return processi


def parse_systemctl(testo):
    """Righe di systemctl list-units --plain --no-legend -> nomi delle unità (es. nginx.service)."""
    unita = []
    for riga in (testo or "").splitlines():
        parti = riga.split()
        if parti and parti[0].endswith(".service"):
            unita.append(parti[0])
    return unita


def _e_runtime(comm):
    """python3.11, node, php8.2... -> True se è il runtime di un'applicazione."""
    return any(re.fullmatch(re.escape(r) + r"[0-9.]*", comm) for r in INT_RUNTIME_APPLICAZIONE)


def _e_database(nome):
    return any(re.fullmatch(re.escape(d) + r"[0-9.]*", nome) for d in INT_PROCESSI_DATABASE)


def _valuta_processi(processi):
    findings = []
    come_root = {}
    for p in processi:
        if p["user"] == "root" and _e_runtime(p["comm"]):
            come_root.setdefault(p["comm"], []).append(p["pid"])
    for comm, pids in sorted(come_root.items()):
        elenco = ", ".join(str(x) for x in pids[:5]) + (" …" if len(pids) > 5 else "")
        findings.append(finding_interno(
            "processi", f"Processo dell'applicazione come root: {comm}", INT_APP_COME_ROOT,
            elemento=f"processo {comm}", evidence=f"ps: utente root, PID {elenco}",
            key=f"root-{comm}"))
    return findings


def _valuta_servizi_attivi(unita):
    findings = []
    for u in unita:
        nome = u.removesuffix(".service")
        base = re.sub(r"[@.].*$", "", nome)
        regola = INT_SERVIZI_SUPERFLUI.get(base)
        if regola:
            findings.append(finding_interno(
                "servizi", f"Servizio superfluo attivo: {nome}", regola, elemento=u,
                evidence=f"systemctl: {u} running", key=f"superfluo-{base}"))
    return findings


def _valuta_porte(servizi):
    findings = []
    for s in servizi:
        nomi = s["processes"]
        if s["all_interfaces"] and any(_e_database(n) for n in nomi):
            pacchetto = (f" · pacchetto {s['package']} {s['package_version'] or ''}".rstrip()
                         if s["package"] else "")
            findings.append(finding_interno(
                "servizi", f"Database in ascolto su tutte le interfacce: {', '.join(nomi)} "
                f"({s['port']}/tcp)", INT_DB_TUTTE_INTERFACCE,
                elemento=f"porta {s['port']}/tcp",
                evidence=f"ss: {', '.join(a or '*' for a in s['addresses'])}:{s['port']} "
                         f"→ {', '.join(nomi)}{pacchetto}",
                port=s["port"], protocol="tcp", package=s["package"], key=f"db-rete-{s['port']}"))
    if servizi:
        righe = []
        for s in servizi:
            dove = "solo localhost" if s["loopback_only"] else ", ".join(a or "*" for a in s["addresses"])
            chi = ", ".join(s["processes"]) or "processo non visibile"
            pkg = f" [{s['package']} {s['package_version'] or ''}]".replace(" ]", "]") if s["package"] else ""
            righe.append(f"{s['port']}/tcp {chi}{pkg} ({dove})")
        findings.append(info_interno(
            "servizi", f"Porte TCP in ascolto: {len(servizi)}", "; ".join(righe),
            elemento="porte in ascolto", key="porte-in-ascolto"))
    return findings


def raccogli(esecutore):
    """Processi, servizi attivi e porte in ascolto. Restituisce (findings, stato, servizi)."""
    findings, note, eseguite = [], [], 0

    if esecutore.which("ps"):
        r, errore = esegui(esecutore, ["ps", "-eo", "user=,pid=,comm="], timeout=30)
        if errore or r.returncode != 0:
            note.append(f"ps non riuscito: {errore or prima_riga(r.stderr)}")
        else:
            eseguite += 1
            findings += _valuta_processi(parse_ps(r.stdout))
    else:
        note.append("ps non presente")

    if esecutore.which("systemctl"):
        r, errore = esegui(esecutore, ["systemctl", "list-units", "--type=service",
                                       "--state=running", "--no-pager", "--no-legend", "--plain"],
                           timeout=30)
        if errore or r.returncode != 0:
            note.append(f"systemctl non riuscito: {errore or prima_riga(r.stderr)}")
        else:
            eseguite += 1
            findings += _valuta_servizi_attivi(parse_systemctl(r.stdout))
    else:
        note.append("systemctl non presente (sistema senza systemd?)")

    servizi = leggi_servizi(esecutore)
    if servizi["stato"]["stato"] != NON_DISPONIBILE:
        eseguite += 1
        findings += _valuta_porte(servizi["services"])
    note_servizi = servizi["stato"]["dettaglio"]

    if eseguite == 0:
        esito = stato(NON_DISPONIBILE, "; ".join(note + [note_servizi]))
    else:
        dettaglio = "; ".join([note_servizi] + note) if note_servizi else "; ".join(note)
        esito = stato(PARZIALE if note or servizi["stato"]["stato"] != ESEGUITO else ESEGUITO,
                      dettaglio)
    return findings, esito, servizi
