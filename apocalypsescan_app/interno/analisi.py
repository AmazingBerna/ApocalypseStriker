"""analisi.py - L'analisi interna completa: mette in fila i raccoglitori.

analisi_interna(esecutore, ...) riceve SOLO un EsecutoreSolaLettura (ogni comando passa
dall'elenco ammesso) e restituisce (findings, meta):
- findings: i finding interni, nello stesso schema di quelli web, con fonte="interno";
- meta: host, sudo, e lo stato di ogni voce ("eseguito", "parziale", "non disponibile: ...").

Regole:
- DEGRADO GRADUALE: un raccoglitore che fallisce (tool mancante, permesso negato, errore
  imprevisto) diventa "non disponibile" con il motivo, e gli altri proseguono;
- RISERVATEZZA: oscura() viene applicato a OGNI finding e a ogni messaggio di stato, con i
  valori segreti noti (password di DB e sudo dalle variabili d'ambiente).
"""
import os

from ..config import INT_ENV_DB_PASSWORD, INT_ENV_SUDO_PASSWORD
from ..risk import sort_findings
from . import codice as codice_mod
from . import database, pacchetti, processi, webserver
from .comandi import EsecutoreSolaLettura
from .comune import NON_DISPONIBILE, non_disponibile, stato
from .riservatezza import oscura_valore

# voce -> etichetta della barra di avanzamento (nell'ordine di esecuzione)
VOCI = {
    "processi": "Processi, servizi e porte in ascolto",
    "database": "Configurazione e permessi del database",
    "codice": "Analisi statica del codice e file sensibili",
    "webserver": "Configurazione del web server",
    "pacchetti": "Pacchetti installati e CVE note",
}


class _SenzaBarra:
    def begin(self, fase, etichetta):
        pass

    def end(self, ok=True):
        pass


def segreti_noti(env=None):
    """I valori da togliere comunque da report e messaggi."""
    env = os.environ if env is None else env
    return [v for v in (env.get(INT_ENV_DB_PASSWORD), env.get(INT_ENV_SUDO_PASSWORD)) if v]


def analisi_interna(esecutore, codice=None, semgrep_rules=None, nvd=False, intel=None,
                    env=None, progress=None, log=None):
    """Esegue l'analisi interna. Non solleva per i problemi della macchina analizzata."""
    if not isinstance(esecutore, EsecutoreSolaLettura):
        raise TypeError("l'analisi interna accetta solo un EsecutoreSolaLettura")
    segreti = segreti_noti(env)
    fasi = progress or _SenzaBarra()
    meta = {"host": esecutore.label, "remoto": bool(esecutore.remote), "sudo": None,
            "codice": codice, "semgrep_rules": semgrep_rules, "voci": {}}

    ok, motivo = esecutore.check_connection()
    if not ok:
        motivo = oscura_valore(f"connessione non riuscita: {motivo}", segreti)
        meta["connessione"] = motivo
        meta["voci"] = {voce: non_disponibile(motivo) for voce in VOCI}
        return [], meta
    meta["connessione"] = "ok"
    meta["sudo"] = bool(esecutore.check_sudo())
    if log and not meta["sudo"]:
        log("[!] sudo non disponibile: alcune voci saranno parziali (es. processi degli altri "
            "utenti, nginx -T).")

    servizi = None
    passi = {
        "processi": lambda: processi.raccogli(esecutore),
        "database": lambda: database.raccogli(esecutore, servizi, env=env),
        "codice": lambda: codice_mod.raccogli(esecutore, codice, semgrep_rules),
        "webserver": lambda: webserver.raccogli(esecutore),
        "pacchetti": lambda: pacchetti.raccogli(esecutore, servizi, nvd=nvd, intel=intel),
    }
    findings = []
    for voce, etichetta in VOCI.items():
        fasi.begin(f"int_{voce}", etichetta)
        try:
            risultato = passi[voce]()
            if voce == "processi":
                nuovi, st, servizi = risultato
            else:
                nuovi, st = risultato
        except Exception as e:       # un raccoglitore non deve mai fermare gli altri
            nuovi, st = [], non_disponibile(f"errore imprevisto ({e.__class__.__name__})")
        findings += nuovi
        meta["voci"][voce] = st
        fasi.end(ok=st["stato"] != NON_DISPONIBILE)
        if log:
            log(f"    {etichetta}: {oscura_valore(st['stato'], segreti)}")

    findings = [oscura_valore(f, segreti) for f in findings]
    meta["voci"] = oscura_valore(meta["voci"], segreti)
    meta["comandi_eseguiti"] = len(esecutore.eseguiti)
    return sort_findings(findings), meta


def riepilogo_stato(meta):
    """Righe "voce: stato - dettaglio" per terminale e report."""
    return [f"{VOCI.get(v, v)}: {s['stato']}" + (f" - {s['dettaglio']}" if s["dettaglio"] else "")
            for v, s in meta.get("voci", {}).items()]


__all__ = ["analisi_interna", "riepilogo_stato", "segreti_noti", "VOCI", "stato"]
