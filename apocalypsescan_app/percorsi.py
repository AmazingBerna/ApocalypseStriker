"""Dove finiscono i report: l'unico punto che calcola i percorsi di output.

Ogni formato ha la sua cartella, con il nome dell'estensione:

    reports/md/   reports/json/   reports/csv/   reports/html/

La radice è sempre quella del progetto, mai la cartella corrente: il report finisce
nello stesso posto da qualunque cartella venga lanciato il comando.

Le scansioni locali girano con sudo (Lynis, Trivy e iptables lo richiedono): tutto
ciò che il programma crea qui viene restituito all'utente che ha lanciato sudo,
altrimenti l'interprete, che gira senza sudo, non potrebbe più scrivere nelle cartelle.
"""
import getpass
import os
import shlex
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
REPORTS = RADICE / "reports"

# estensioni riconosciute in --output (Report-WSL.json -> Report-WSL)
ESTENSIONI = (".md", ".json", ".csv", ".html")

SUFFISSO_INTERPRETAZIONE = "_interpretazione"


def restituisci_proprieta(percorso):
    """Se il programma gira come root tramite sudo, restituisce il percorso all'utente
    che ha lanciato sudo (SUDO_UID/SUDO_GID). Altrimenti non fa nulla."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and uid and gid:
        os.chown(percorso, int(uid), int(gid))


def crea_cartella(cartella):
    """mkdir(parents=True) che restituisce all'utente anche le cartelle intermedie create."""
    cartella = Path(cartella)
    nuove = []
    corrente = cartella
    while not corrente.exists():
        nuove.append(corrente)
        if corrente.parent == corrente:
            break
        corrente = corrente.parent
    cartella.mkdir(parents=True, exist_ok=True)
    for c in reversed(nuove):
        restituisci_proprieta(c)
    return cartella


def cartella_report(formato):
    """RADICE/reports/<formato>/, creata se manca e di proprietà dell'utente.

    reports/ e la cartella del formato vengono restituite anche se esistono già:
    così si sistemano da sole quelle create da root dalle versioni precedenti."""
    cartella = crea_cartella(REPORTS / formato)
    restituisci_proprieta(REPORTS)
    restituisci_proprieta(cartella)
    return cartella


def percorso_report(nome, formato):
    """RADICE/reports/<formato>/<nome>.<formato>"""
    return cartella_report(formato) / f"{nome}.{formato}"


def _nome_base(percorso):
    """Il nome del file senza l'estensione, se è una di quelle dei report."""
    percorso = Path(percorso)
    return percorso.stem if percorso.suffix.lower() in ESTENSIONI else percorso.name


def _in_reports(cartella):
    """True se cartella è reports/ o una delle sue sottocartelle per formato."""
    cartella = Path(cartella).resolve()
    return cartella == REPORTS or cartella.parent == REPORTS


def percorso_output(output, formato, suffisso=""):
    """Il percorso del report nel formato indicato, a partire da --output.

      Report-WSL                 -> reports/<formato>/Report-WSL.<formato>
      Report-WSL.json            -> come sopra (l'estensione viene tolta)
      reports/Report-WSL         -> come sopra (è già la cartella dei report)
      ~/Desktop/rep              -> ~/Desktop/rep.<formato>: la cartella chiesta
                                    esplicitamente viene rispettata
    """
    percorso = Path(output).expanduser()
    nome = _nome_base(percorso) + suffisso
    if str(percorso.parent) == "." or _in_reports(percorso.parent):
        return percorso_report(nome, formato)
    return crea_cartella(percorso.parent) / f"{nome}.{formato}"


def percorso_interpretazione(report, output=None):
    """Dove salvare la lettura guidata (Markdown) di un report.

    Con output (--output dell'interprete) vale la regola di percorso_output.
    Senza, un report in reports/ dà reports/md/<nome>_interpretazione.md; un report
    salvato altrove con --output ha l'interpretazione accanto, nella stessa cartella.
    """
    if output:
        return percorso_output(output, "md")
    return percorso_output(report, "md", SUFFISSO_INTERPRETAZIONE)


def scrivi(percorso, testo, encoding="utf-8"):
    """Scrive il file e lo restituisce all'utente che ha lanciato sudo."""
    percorso = Path(percorso)
    percorso.write_text(testo, encoding=encoding)
    restituisci_proprieta(percorso)
    return percorso


def report_salvati(formato):
    """I report del formato in reports/<formato>/, dal più recente."""
    cartella = REPORTS / formato
    if not cartella.is_dir():
        return []
    return sorted(cartella.glob(f"*.{formato}"), key=lambda p: p.stat().st_mtime, reverse=True)


def comando_ripristino(percorso=None):
    """Il comando che restituisce all'utente i file creati da root: tutto reports/ se
    il percorso è lì dentro (o non è noto), altrimenti solo quel percorso."""
    utente = os.environ.get("SUDO_USER") or getpass.getuser()
    bersaglio = REPORTS
    if percorso:
        percorso = Path(percorso).resolve()
        if REPORTS not in (percorso, *percorso.parents):
            bersaglio = percorso
    return f"sudo chown -R {shlex.quote(utente)}: {shlex.quote(str(bersaglio))}"
