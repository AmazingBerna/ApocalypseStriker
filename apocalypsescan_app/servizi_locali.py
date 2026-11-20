"""servizi_locali.py - Servizi in ascolto sulla macchina analizzata: porta -> processo -> pacchetto.

Raccoglitore a sé stante, usato dall'analisi interna (apocalypse inspect):
1. `ss -H -tlnp` elenca le porte TCP in ascolto e, con i privilegi (sudo), il processo;
2. `readlink -f /proc/PID/exe` dà l'eseguibile del processo;
3. `dpkg-query -S` (Debian/Ubuntu) o `rpm -qf` (RHEL/Fedora/SUSE) dicono a quale pacchetto
   appartiene, e `dpkg-query -W` ne dà la versione.

Tutti i comandi passano dall'EsecutoreSolaLettura. Senza sudo `ss` non mostra i processi
degli altri utenti: le porte restano elencate e il resto risulta "non disponibile".

Restituisce:
    {"manager": "dpkg" | "rpm" | None,
     "services": [{"protocol", "port", "addresses", "processes", "pids", "exe",
                   "package", "package_version", "loopback_only", "all_interfaces"}],
     "stato": {"stato": ..., "dettaglio": ...}}
"""
import re

from .interno.comune import ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, prima_riga, stato

_PROCESSO = re.compile(r'\("([^"]+)",pid=(\d+)')
_TUTTE = {"0.0.0.0", "::", "*", ""}


def _loopback(indirizzo):
    return indirizzo.startswith("127.") or indirizzo in ("::1", "localhost")


def parse_ss(testo):
    """Righe di `ss -H -tlnp` -> servizi raggruppati per porta (senza pacchetti)."""
    servizi = {}
    for riga in (testo or "").splitlines():
        parti = riga.split()
        if len(parti) < 4 or parti[0] != "LISTEN":
            continue
        indirizzo, _, porta = parti[3].rpartition(":")
        if not porta.isdigit():
            continue
        indirizzo = indirizzo.strip("[]").split("%")[0]   # [::1] -> ::1, 127.0.0.53%lo -> 127.0.0.53
        s = servizi.setdefault(int(porta), {
            "protocol": "tcp", "port": int(porta), "addresses": [], "processes": [], "pids": [],
            "exe": None, "package": None, "package_version": None,
        })
        if indirizzo not in s["addresses"]:
            s["addresses"].append(indirizzo)
        for nome, pid in _PROCESSO.findall(" ".join(parti[5:])):
            if nome not in s["processes"]:
                s["processes"].append(nome)
            if int(pid) not in s["pids"]:
                s["pids"].append(int(pid))
    elenco = []
    for porta in sorted(servizi):
        s = servizi[porta]
        s["loopback_only"] = all(_loopback(a) for a in s["addresses"])
        s["all_interfaces"] = any(a in _TUTTE for a in s["addresses"])
        elenco.append(s)
    return elenco


def _gestore(esecutore):
    if esecutore.which("dpkg-query"):
        return "dpkg"
    if esecutore.which("rpm"):
        return "rpm"
    return None


def _pacchetto(esecutore, gestore, exe):
    """(pacchetto, versione) dell'eseguibile, o (None, None) se non appartiene a un pacchetto."""
    if gestore == "dpkg":
        r, errore = esegui(esecutore, ["dpkg-query", "-S", exe], timeout=30)
        if errore or r.returncode != 0 or ":" not in r.stdout:
            return None, None
        nome = r.stdout.split(":", 1)[0].split(",")[0].strip()
        r, errore = esegui(esecutore, ["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n", nome],
                           timeout=30)
        versione = None
        if not errore and r.returncode == 0 and "\t" in r.stdout:
            versione = r.stdout.splitlines()[0].split("\t", 1)[1].strip()
        return nome, versione
    if gestore == "rpm":
        r, errore = esegui(esecutore, ["rpm", "-qf", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n", exe],
                           timeout=30)
        if errore or r.returncode != 0 or "\t" not in r.stdout:
            return None, None
        nome, versione = r.stdout.splitlines()[0].split("\t", 1)
        return nome.strip(), versione.strip()
    return None, None


def leggi_servizi(esecutore):
    """Servizi TCP in ascolto con processo e pacchetto. Non solleva mai: i problemi finiscono
    in "stato"."""
    if not esecutore.which("ss"):
        return {"manager": None, "services": [],
                "stato": stato(NON_DISPONIBILE, "comando ss non presente sulla macchina")}
    r, errore = esegui(esecutore, ["ss", "-H", "-tlnp"], sudo=True, timeout=30)
    if errore or r.returncode != 0:
        motivo = errore or prima_riga(r.stderr) or f"ss ha restituito {r.returncode}"
        return {"manager": None, "services": [],
                "stato": stato(NON_DISPONIBILE, f"ss non riuscito: {motivo}")}

    servizi = parse_ss(r.stdout)
    note = []
    if servizi and not any(s["pids"] for s in servizi):
        note.append("processi non visibili (servono i privilegi di sudo per ss -p)")
    gestore = _gestore(esecutore) if any(s["pids"] for s in servizi) else None
    if any(s["pids"] for s in servizi) and gestore is None:
        note.append("né dpkg né rpm presenti: pacchetti non identificati")

    exe_negati = 0
    for s in servizi:
        if not s["pids"]:
            continue
        r, errore = esegui(esecutore, ["readlink", "-f", f"/proc/{s['pids'][0]}/exe"],
                           sudo=True, timeout=30)
        if errore or r.returncode != 0 or not r.stdout.strip().startswith("/"):
            exe_negati += 1
            continue
        s["exe"] = r.stdout.strip()
        if gestore:
            s["package"], s["package_version"] = _pacchetto(esecutore, gestore, s["exe"])
    if exe_negati:
        note.append(f"eseguibile non leggibile per {exe_negati} servizi")

    esito = PARZIALE if note else ESEGUITO
    dettaglio = f"{len(servizi)} porte TCP in ascolto" + (f"; {'; '.join(note)}" if note else "")
    return {"manager": gestore, "services": servizi, "stato": stato(esito, dettaglio)}
