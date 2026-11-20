"""comune.py - Aiuti condivisi dai raccoglitori dell'analisi interna.

Ogni raccoglitore restituisce (findings, stato):
- findings: finding nello stesso schema di quelli web (make_finding/info_finding), con in
  più fonte="interno" ed elemento (cosa è interessato: porta, utente del DB, file:riga...);
- stato: {"stato": "eseguito" | "parziale" | "non disponibile", "dettaglio": testo}.
Un raccoglitore non solleva MAI per un problema della macchina analizzata (tool mancante,
permesso negato, timeout): lo scrive nello stato e l'analisi prosegue con le altre voci.
"""
import subprocess

from ..config import INT_TIMEOUT, OWASP
from ..risk import info_finding, make_finding

ESEGUITO = "eseguito"
PARZIALE = "parziale"
NON_DISPONIBILE = "non disponibile"


def stato(esito, dettaglio=""):
    return {"stato": esito, "dettaglio": dettaglio}


def non_disponibile(motivo):
    return stato(NON_DISPONIBILE, motivo)


def finding_interno(source, item, regola, elemento, evidence, **extra):
    """Finding interno da una regola di config.py (owasp, impatto, probabilità, motivazione)."""
    owasp_key, impatto, prob, motivo = regola
    extra.setdefault("reason", motivo)
    reason = extra.pop("reason")
    return make_finding(source, item, impatto, prob, reason, owasp=OWASP[owasp_key],
                        url=None, evidence=evidence, fonte="interno", elemento=elemento,
                        **extra)


def info_interno(source, item, reason, elemento=None, evidence=None, **extra):
    return info_finding(source, item, reason, owasp=None, url=None, evidence=evidence,
                        fonte="interno", elemento=elemento, **extra)


def esegui(esecutore, args, input=None, sudo=False, sudo_user=None, timeout=INT_TIMEOUT):
    """Esegue un comando ammesso e restituisce (risultato, errore). errore è None se il
    comando è partito (anche con codice di uscita diverso da 0), altrimenti il motivo:
    i problemi di esecuzione non interrompono l'analisi."""
    try:
        risultato = esecutore.run(args, input=input, sudo=sudo, sudo_user=sudo_user,
                                  timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timeout dopo {timeout} s"
    except OSError as e:
        return None, f"esecuzione non riuscita ({e.__class__.__name__})"
    return risultato, None


def prima_riga(testo, massimo=200):
    """Prima riga non vuota di un messaggio d'errore, accorciata: per i motivi di stato."""
    for riga in (testo or "").splitlines():
        if riga.strip():
            riga = riga.strip()
            return riga if len(riga) <= massimo else riga[:massimo] + "…"
    return ""


def permesso_negato(testo):
    basso = (testo or "").lower()
    return any(s in basso for s in ("permission denied", "a password is required",
                                    "sudo:", "operation not permitted", "access denied"))
