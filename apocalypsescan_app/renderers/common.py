"""Contenuti condivisi dai renderer leggibili (Markdown e HTML).

Qui stanno i dati, non la formattazione: ogni renderer li impagina a modo suo.
Nei testi, `x` indica un nome da mostrare come codice.
"""
from ..config import ESITI_PT, ESITI_PT_DESCRIZIONE, RISK_THRESHOLDS
from ..web.esito_pt import esito_di, fonte_di

SCORED_LEVELS = ("Critico", "Alto", "Medio", "Basso")


def percent(value):
    """0.94321 -> '94,32%'; i valori che arrotondati darebbero 100% restano '>99,99%'."""
    if value >= 0.99995:
        return ">99,99%"
    return f"{value * 100:.2f}%".replace(".", ",")


def elemento(f):
    """Cosa è interessato dal finding: l'elemento dell'analisi interna (porta, utente del DB,
    file:riga...) o l'URL del finding web."""
    return f.get("elemento") or f.get("url")


def conteggi_fonte(findings, livello):
    """(esterni, interni) dei finding valutati di quel livello."""
    del_livello = [f for f in findings if f.get("impact") is not None and f["level"] == livello]
    interni = sum(1 for f in del_livello if fonte_di(f) == "interno")
    return len(del_livello) - interni, interni


def righe_esiti(findings):
    """(esito, numero di finding, significato) per ogni esito presente, nell'ordine di ESITI_PT."""
    conteggi = {}
    for f in findings:
        conteggi[esito_di(f)] = conteggi.get(esito_di(f), 0) + 1
    return [(e, conteggi[e], ESITI_PT_DESCRIZIONE[e]) for e in ESITI_PT if conteggi.get(e)]


def thresholds_text():
    """'16-25 = Critico, 10-15 = Alto, ...'"""
    parts = []
    upper = 25
    for minimum, level in RISK_THRESHOLDS:
        parts.append(f"{minimum}-{upper} = {level}")
        upper = minimum - 1
    return ", ".join(parts)
