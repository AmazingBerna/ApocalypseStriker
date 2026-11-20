"""risk.py - Il modello di rischio comune: rischio = impatto x probabilità.

Le funzioni del vecchio report "host" (porte di Nmap) sono archiviate in
docs/archivio/report_host/risk_host.py.
"""
from .config import RISK_THRESHOLDS


def risk_level(score):
    """Converte il punteggio impatto x probabilità (1-25) in un livello."""
    for minimum, level in RISK_THRESHOLDS:
        if score >= minimum:
            return level
    return "Informativo"


def make_finding(source, item, impact, probability, reason, **extra):
    """Crea un finding con rischio = impatto x probabilità."""
    score = impact * probability
    return {
        "source": source,
        "item": item,
        "impact": impact,
        "probability": probability,
        "score": score,
        "level": risk_level(score),
        "reason": reason,
        **extra,
    }


def info_finding(source, item, reason, **extra):
    """Finding puramente informativo: non entra nel calcolo del rischio."""
    return {
        "source": source,
        "item": item,
        "impact": None,
        "probability": None,
        "score": 0,
        "level": "Informativo",
        "reason": reason,
        **extra,
    }


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f["score"], f["impact"] or 0), reverse=True)
