"""codice.py - Analisi statica del codice sorgente e file sensibili nella cartella del codice.

- Bandit (Python), se installato sulla macchina: `bandit -r CODICE -f json -q`.
- Semgrep, SOLO se si indica un file/cartella di regole LOCALE (--semgrep-rules): sempre con
  --metrics=off e --disable-version-check. Mai --config auto (scaricherebbe regole da internet).
- File sensibili (.env, chiavi, dump .sql, backup...): `find` ne elenca i NOMI, `stat` i
  permessi. Il contenuto non viene mai letto.

Riservatezza: dei risultati di Bandit e Semgrep si tengono solo regola, gravità, file e riga.
Il frammento di codice ("code", "lines") viene SEMPRE scartato; per le regole sui segreti
(B105-B107) anche il testo del problema, che contiene il valore trovato, è sostituito da una
descrizione fissa.
"""
import json
import re

from ..config import (INT_BANDIT_OWASP, INT_BANDIT_SEGRETI, INT_CODICE_IMPATTO,
                      INT_CODICE_MAX_POSIZIONI, INT_CODICE_PROBABILITA,
                      INT_CODICE_PROBABILITA_DEFAULT, INT_CODICE_SEGRETO, INT_FILE_LEGGIBILE,
                      INT_FILE_SENSIBILE_PRESENTE, INT_FILE_SISTEMA, INT_LOG_LEGGIBILE)
from .comandi import PERCORSO, _FIND_NOMI
from .comune import (ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, finding_interno, prima_riga,
                     stato)

_VIRGOLETTE = re.compile(r"(['\"]).*?\1")


def _testo_sicuro(testo):
    """Toglie i letterali tra virgolette dal testo di un problema: possono contenere valori."""
    return _VIRGOLETTE.sub("'…'", testo or "").strip()


def _posizioni(voci, radice):
    def corto(p):
        return p[len(radice):].lstrip("/") if radice and p.startswith(radice) else p
    elenco = [f"{corto(v['file'])}:{v['riga']}" for v in voci[:INT_CODICE_MAX_POSIZIONI]]
    if len(voci) > INT_CODICE_MAX_POSIZIONI:
        elenco.append(f"e altre {len(voci) - INT_CODICE_MAX_POSIZIONI}")
    return ", ".join(elenco)


# ==========================================================================
# Bandit
# ==========================================================================

def parse_bandit(testo):
    """JSON di Bandit -> [{regola, nome, gravita, confidenza, testo, file, riga}], SENZA il codice."""
    dati = json.loads(testo or "{}")
    voci = []
    for r in dati.get("results", []):
        regola = r.get("test_id", "?")
        segreto = regola in INT_BANDIT_SEGRETI
        voci.append({
            "regola": regola,
            "nome": r.get("test_name", ""),
            "gravita": (r.get("issue_severity") or "").upper(),
            "confidenza": (r.get("issue_confidence") or "").upper(),
            # mai il valore: per i segreti un testo fisso, per gli altri senza letterali
            "testo": "Credenziale scritta nel codice" if segreto else _testo_sicuro(r.get("issue_text")),
            "file": r.get("filename", "?"),
            "riga": r.get("line_number", "?"),
            "segreto": segreto,
        })
    return voci


def _finding_bandit(voci, radice):
    """Un finding per regola di Bandit (con le posizioni), invece di uno per riga."""
    per_regola = {}
    for v in voci:
        per_regola.setdefault(v["regola"], []).append(v)
    findings = []
    for regola, gruppo in sorted(per_regola.items()):
        primo = gruppo[0]
        dove = _posizioni(gruppo, radice)
        if primo["segreto"]:
            findings.append(finding_interno(
                "bandit", f"Bandit {regola}: credenziale scritta nel codice ({len(gruppo)})",
                INT_CODICE_SEGRETO, elemento=f"{primo['file']}:{primo['riga']}",
                evidence=f"{regola} {primo['nome']} in {dove}", references=[regola],
                key=f"bandit-{regola}"))
            continue
        impatto = max(INT_CODICE_IMPATTO.get(v["gravita"], 2) for v in gruppo)
        prob = max(INT_CODICE_PROBABILITA.get(v["confidenza"], INT_CODICE_PROBABILITA_DEFAULT)
                   for v in gruppo)
        owasp = INT_BANDIT_OWASP.get(regola[:2], "A05")
        motivo = (f"{primo['testo']} (Bandit, gravità {primo['gravita'] or '?'}, confidenza "
                  f"{primo['confidenza'] or '?'}). Analisi statica: va verificata nel contesto "
                  "del codice prima di correggerla.")
        findings.append(finding_interno(
            "bandit", f"Bandit {regola} {primo['nome']} ({len(gruppo)})",
            (owasp, impatto, prob, motivo), elemento=f"{primo['file']}:{primo['riga']}",
            evidence=f"{regola} in {dove}", references=[regola], key=f"bandit-{regola}"))
    return findings


def _bandit(esecutore, codice):
    if not esecutore.which("bandit"):
        return [], "Bandit non installato sulla macchina"
    r, errore = esegui(esecutore, ["bandit", "-r", codice, "-f", "json", "-q"], timeout=600)
    if errore:
        return None, f"Bandit non riuscito: {errore}"
    # Bandit esce con 1 quando trova problemi: conta solo che il JSON sia leggibile
    try:
        voci = parse_bandit(r.stdout)
    except (json.JSONDecodeError, AttributeError):
        return None, f"Bandit non riuscito: {prima_riga(r.stderr) or 'output non leggibile'}"
    return _finding_bandit(voci, codice), f"Bandit: {len(voci)} problemi"


# ==========================================================================
# Semgrep (solo regole locali)
# ==========================================================================

def parse_semgrep(testo):
    dati = json.loads(testo or "{}")
    voci = []
    for r in dati.get("results", []):
        extra = r.get("extra", {}) or {}
        voci.append({
            "regola": r.get("check_id", "?"),
            "gravita": (extra.get("severity") or "").upper(),
            "testo": _testo_sicuro(extra.get("message")),     # mai extra["lines"] (il codice)
            "file": r.get("path", "?"),
            "riga": (r.get("start") or {}).get("line", "?"),
        })
    return voci


def _finding_semgrep(voci, radice):
    per_regola = {}
    for v in voci:
        per_regola.setdefault(v["regola"], []).append(v)
    findings = []
    for regola, gruppo in sorted(per_regola.items()):
        primo = gruppo[0]
        impatto = max(INT_CODICE_IMPATTO.get(v["gravita"], 2) for v in gruppo)
        motivo = (f"{primo['testo'][:300]} (Semgrep, gravità {primo['gravita'] or '?'}). "
                  "Analisi statica: va verificata nel contesto del codice.")
        breve = regola.rsplit(".", 1)[-1]
        findings.append(finding_interno(
            "semgrep", f"Semgrep {breve} ({len(gruppo)})",
            ("A03" if "inject" in regola.lower() or "sql" in regola.lower() else "A05",
             impatto, INT_CODICE_PROBABILITA_DEFAULT, motivo),
            elemento=f"{primo['file']}:{primo['riga']}", evidence=f"{regola} in {_posizioni(gruppo, radice)}",
            references=[regola], key=f"semgrep-{regola}"))
    return findings


def _semgrep(esecutore, codice, regole):
    if not regole:
        return [], None          # Semgrep non richiesto: non è un'assenza da segnalare
    if not PERCORSO.accetta(regole):
        return None, "Semgrep: --semgrep-rules deve essere un percorso assoluto sulla macchina"
    if not esecutore.which("semgrep"):
        return None, "Semgrep non installato sulla macchina"
    args = ["semgrep", "scan", "--config", regole, "--metrics=off", "--disable-version-check",
            "--json", "--quiet", codice]
    r, errore = esegui(esecutore, args, timeout=900)
    if errore:
        return None, f"Semgrep non riuscito: {errore}"
    try:
        voci = parse_semgrep(r.stdout)
    except (json.JSONDecodeError, AttributeError):
        return None, f"Semgrep non riuscito: {prima_riga(r.stderr) or 'output non leggibile'}"
    return _finding_semgrep(voci, codice), f"Semgrep: {len(voci)} problemi"


# ==========================================================================
# File sensibili e permessi (solo nomi e permessi, mai il contenuto)
# ==========================================================================

def parse_stat(testo):
    """Righe "permessi|utente|gruppo|percorso" -> [{modo, utente, gruppo, percorso}]."""
    voci = []
    for riga in (testo or "").splitlines():
        parti = riga.split("|", 3)
        if len(parti) == 4 and re.fullmatch(r"[0-7]{3,4}", parti[0]):
            voci.append({"modo": parti[0], "utente": parti[1], "gruppo": parti[2], "percorso": parti[3]})
    return voci


def _leggibile_da_tutti(modo):
    return int(modo[-1]) & 4 == 4


def _stat(esecutore, percorsi):
    if not percorsi:
        return []
    r, errore = esegui(esecutore, ["stat", "-c", "%a|%U|%G|%n", *percorsi], sudo=True, timeout=60)
    if errore:
        return []
    return parse_stat(r.stdout)        # stat esce con 1 se qualche percorso manca: va bene


def _file_sensibili(esecutore, codice):
    """Finding sui file sensibili nel codice e sui permessi di configurazioni e log."""
    findings, note = [], []
    trovati = []
    if codice:
        if esecutore.which("find"):
            r, errore = esegui(esecutore, ["find", codice, "-xdev", "-maxdepth", "6", "-type", "f",
                                           "(", *_FIND_NOMI, ")", "-print"], sudo=True, timeout=120)
            if errore or (r.returncode != 0 and not r.stdout.strip()):
                motivo = errore or prima_riga(r.stderr) or f"find ha restituito {r.returncode}"
                note.append(f"ricerca dei file sensibili non riuscita: {motivo}")
            else:
                trovati = [p for p in r.stdout.splitlines() if PERCORSO.accetta(p.strip())][:100]
        else:
            note.append("find non presente")
    for v in _stat(esecutore, trovati):
        nome = v["percorso"]
        if _leggibile_da_tutti(v["modo"]):
            findings.append(finding_interno(
                "file", f"File sensibile leggibile da tutti: {nome.rsplit('/', 1)[-1]}",
                INT_FILE_LEGGIBILE, elemento=nome,
                evidence=f"permessi {v['modo']}, proprietario {v['utente']}:{v['gruppo']}",
                key=f"file-leggibile-{nome}"))
        else:
            findings.append(finding_interno(
                "file", f"File sensibile nella cartella del codice: {nome.rsplit('/', 1)[-1]}",
                INT_FILE_SENSIBILE_PRESENTE, elemento=nome,
                evidence=f"permessi {v['modo']}, proprietario {v['utente']}:{v['gruppo']}",
                key=f"file-presente-{nome}"))
    for v in _stat(esecutore, list(INT_FILE_SISTEMA)):
        if not _leggibile_da_tutti(v["modo"]):
            continue
        if v["percorso"].startswith("/var/log/"):
            regola = INT_LOG_LEGGIBILE
        elif v["percorso"].endswith(("debian.cnf", ".my.cnf")):
            regola = INT_FILE_LEGGIBILE
        else:
            continue       # nginx.conf, my.cnf leggibili da tutti sono la norma
        findings.append(finding_interno(
            "file", f"Leggibile da tutti: {v['percorso']}", regola, elemento=v["percorso"],
            evidence=f"permessi {v['modo']}, proprietario {v['utente']}:{v['gruppo']}",
            key=f"sistema-leggibile-{v['percorso']}"))
    return findings, note, len(trovati)


def raccogli(esecutore, codice=None, semgrep_rules=None):
    """Analisi statica e file sensibili. Restituisce (findings, stato)."""
    if codice is not None and not PERCORSO.accetta(codice):
        return [], stato(NON_DISPONIBILE, "percorso del codice non valido: serve un percorso assoluto")
    findings, dettagli, mancanti = [], [], []
    if codice:
        for analisi in (lambda: _bandit(esecutore, codice),
                        lambda: _semgrep(esecutore, codice, semgrep_rules)):
            nuovi, messaggio = analisi()
            if nuovi is None:
                mancanti.append(messaggio)
                continue
            if messaggio and not nuovi and "non installato" in messaggio:
                mancanti.append(messaggio)
                continue
            findings += nuovi
            if messaggio:
                dettagli.append(messaggio)
    else:
        mancanti.append("analisi statica non eseguita: percorso del codice non indicato (--code)")

    nuovi, note, n_file = _file_sensibili(esecutore, codice)
    findings += nuovi
    if codice:
        dettagli.append(f"{n_file} file sensibili trovati nel codice")
    mancanti += note

    if not dettagli:
        return findings, stato(NON_DISPONIBILE, "; ".join(mancanti))
    esito = PARZIALE if mancanti else ESEGUITO
    return findings, stato(esito, "; ".join(dettagli + mancanti))
