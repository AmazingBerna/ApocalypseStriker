"""esito_pt.py - L'esito della verifica di penetration testing per ogni finding.

Cinque valori (config.ESITI_PT):
- "confermato":      il PT attivo ha dimostrato il problema. Vale per i finding del PT, e per
                     i finding passivi collegati a una classe che il PT ha confermato;
- "non confermato":  il PT ha provato la classe collegata, ma non l'ha dimostrata;
- "da verificare":   candidato del PT senza conferma attiva (es. SSRF): da controllare a mano;
- "non testato":     finding passivo senza test attivo corrispondente, o PT non eseguito;
- "non applicabile": finding dell'analisi interna.

Il collegamento passivo -> attivo è in config.PT_COLLEGAMENTO_PASSIVO (es. CSP assente ->
classe xss). La classe di un finding attivo viene dalla sua key "pt-<classe>-...".

assegna_esiti() lavora sui finding GREZZI (prima della normalizzazione, quando hanno ancora
la key) e aggiunge "esito_pt" ed "esito_pt_nota". esito_di() ricava l'esito anche dai
modelli salvati con le versioni precedenti, che non hanno il campo.
"""
import re

from ..config import (ESITO_CONFERMATO, ESITO_DA_VERIFICARE, ESITO_NON_APPLICABILE,
                      ESITO_NON_CONFERMATO, ESITO_NON_TESTATO, PT_COLLEGAMENTO_PASSIVO,
                      PT_NOME_CLASSE)


def classe_attiva(f):
    """'sqli', 'xss'... dalla key pt-<classe>-...; None se il finding non è del PT."""
    m = re.match(r"pt-([a-z]+)-", f.get("key") or "")
    return m.group(1) if m else None


def classe_collegata(f):
    """La classe del PT che corrisponde a un finding passivo, o None."""
    voce = (f.get("item") or "").lower()
    for fonte, espressione, classe in PT_COLLEGAMENTO_PASSIVO:
        if f.get("source") == fonte and re.search(espressione, voce):
            return classe
    return None


def _nome(classe):
    return PT_NOME_CLASSE.get(classe, classe)


def assegna_esiti(findings, pentest=None):
    """Aggiunge esito_pt ed esito_pt_nota a ogni finding (li modifica sul posto).
    pentest: il meta del penetration testing (con "classi_provate"), None se non eseguito."""
    confermate = {}
    for f in findings:
        if f.get("source") == "pentest" and f.get("impact") is not None:
            classe = classe_attiva(f)
            if classe:
                confermate.setdefault(classe, []).append(f.get("item"))
    provate = (pentest or {}).get("classi_provate") or {}

    for f in findings:
        nota = None
        if f.get("fonte") == "interno":
            esito = ESITO_NON_APPLICABILE
        elif f.get("source") == "pentest":
            if f.get("impact") is not None:
                esito = ESITO_CONFERMATO
            else:
                esito = ESITO_DA_VERIFICARE
                nota = "candidato del test attivo, non confermabile in automatico: verificare a mano"
        else:
            classe = classe_collegata(f)
            if classe is None:
                esito = ESITO_NON_TESTATO
            elif pentest is None:
                esito = ESITO_NON_TESTATO
                nota = f"collegato al test di {_nome(classe)}: penetration testing non eseguito"
            elif classe in confermate:
                esito = ESITO_CONFERMATO
                nota = f"{_nome(classe)} confermato dal test attivo: {confermate[classe][0]}"
            elif provate.get(classe):
                esito = ESITO_NON_CONFERMATO
                n = provate[classe]
                nota = (f"{_nome(classe)} provato su {n} {'punto' if n == 1 else 'punti'} di input: "
                        "nessuna conferma")
            else:
                esito = ESITO_NON_TESTATO
                nota = f"{_nome(classe)} non provato: nessun punto di input adatto raggiunto"
        f["esito_pt"] = esito
        f["esito_pt_nota"] = nota
    return findings


def esito_di(f):
    """L'esito del finding; per i modelli senza il campo (versioni precedenti) lo ricava
    dalla sola fonte, senza i collegamenti passivo -> attivo."""
    if f.get("esito_pt"):
        return f["esito_pt"]
    if f.get("fonte") == "interno":
        return ESITO_NON_APPLICABILE
    if f.get("source") == "pentest":
        return ESITO_CONFERMATO if f.get("impact") is not None else ESITO_DA_VERIFICARE
    return ESITO_NON_TESTATO


def fonte_di(f):
    return f.get("fonte") or "esterno"
