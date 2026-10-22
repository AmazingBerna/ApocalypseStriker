#!/usr/bin/env python3
"""
menu_stile.py - Stile condiviso del menù di ApocalypseStriker (sempre fucsia)
============================================================================

I primitivi di presentazione del menù (banner, cornici, colori, domande), estratti
per essere usati dal menù web senza dipendere dal menù host. ApocalypseStriker è la
forma risvegliata del drago: qui il tema è sempre fucsia (banner.FUCSIA), mai rosso.

Lo stile replica quello delle versioni precedenti: larghezza 78, wordmark "ANSI
Shadow", stesse domande e cornici. Nessuna dipendenza dai moduli di scansione host.
"""

import os
import re
import shutil
import sys

from . import banner
from .web.recon import normalizza_url

LARGHEZZA = 78

# Lettere a blocchi pieni con ombra a doppia linea (stile "ANSI Shadow")
BANNER = """
 █████╗ ██████╗  ██████╗  ██████╗ █████╗ ██╗  ██╗   ██╗██████╗ ███████╗███████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔══██╗██║  ╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝
███████║██████╔╝██║   ██║██║     ███████║██║   ╚████╔╝ ██████╔╝███████╗█████╗
██╔══██║██╔═══╝ ██║   ██║██║     ██╔══██║██║    ╚██╔╝  ██╔═══╝ ╚════██║██╔══╝
██║  ██║██║     ╚██████╔╝╚██████╗██║  ██║███████╗██║   ██║     ███████║███████╗
╚═╝  ╚═╝╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝     ╚══════╝╚══════╝
"""

# Versione compatta, per i terminali troppo stretti per il banner grande
BANNER_PICCOLO = r"""
                             _
                            | |
  __ _ _ __   ___   ___ __ _| |_   _ _ __  ___  ___
 / _` | '_ \ / _ \ / __/ _` | | | | | '_ \/ __|/ _ \
| (_| | |_) | (_) | (_| (_| | | |_| | |_) \__ \  __/
 \__,_| .__/ \___/ \___\__,_|_|\__, | .__/|___/\___|
      | |                       __/ | |
      |_|                      |___/|_|
"""


# --------------------------------------------------------------------------
# Colori: la palette fucsia del drago (banner.FUCSIA), una sola per Striker
# --------------------------------------------------------------------------

# Stessa disciplina dell'animazione: niente sequenze ANSI fuori da un terminale o con NO_COLOR
USA_COLORI = banner._enabled(sys.stdout)

RESET = banner.RESET
GRASSETTO = "\033[1m"
GRIGIO = "\033[38;5;245m"         # descrizioni e note
ARANCIO = "\033[38;5;208m"        # opzioni della riga di comando
AVVISO = "\033[1;38;5;196m"       # avvisi ed errori

# Il tema fucsia, preso dalla palette del drago (come il Tema PRIMAL delle versioni precedenti)
_P = banner.FUCSIA
ACCENTO = _P.head       # le teste del drago: accenti
CORNICE = _P.body       # il corpo: linee di separazione
TITOLO = _P.title       # intestazioni e numeri delle voci
AZIONE = _P.lit         # comandi e azioni (le teste accese)
FIAMMA = _P.fire        # sfumatura delle lettere del banner
OMBRA = _P.scales       # l'ombra delle lettere del banner

# Livelli di rischio, dal più grave
COLORE_RISCHIO = {
    "Critico": "\033[1;38;5;196m",
    "Alto": "\033[1;38;5;208m",
    "Medio": "\033[1;38;5;220m",
    "Basso": "\033[1;38;5;46m",
}


def c(testo, colore):
    """Colora il testo, se i colori sono attivi."""
    return f"{colore}{testo}{RESET}" if USA_COLORI and testo else testo


def colora_testo(testo):
    """Colora una sezione della guida: "# " titolo, "$ " comando, "! " avviso."""
    righe, avviso, comando = [], False, False
    for r in testo.split("\n"):
        s = r.strip()
        if not s:
            avviso = comando = False
            righe.append(r)
        elif r.startswith("# "):
            righe.append(c(r[2:], TITOLO))
        elif r.startswith("! ") or (avviso and r.startswith("  ")):
            avviso = True
            righe.append(c(r, AVVISO))
        elif s.startswith("$ ") or comando:
            comando = s.endswith("\\")
            righe.append(c(r, AZIONE))
        elif m := re.match(r"^(\s*)(--.+?)(\s{2,})(.*)$", r):
            righe.append(m[1] + c(m[2], ARANCIO) + m[3] + m[4])
        elif m := re.match(r"^(\s*)(\[\d\])(\s+)(.+?)(\s{2,})(.*)$", r):
            righe.append(m[1] + c(m[2], ACCENTO) + m[3] + c(m[4], GRASSETTO) + m[5] + m[6])
        elif m := re.match(r"^(\s*\d+ - +\d+\s+)(Critico|Alto|Medio|Basso)$", r):
            righe.append(c(r, COLORE_RISCHIO[m[2]]))
        elif s.startswith("Rischio ="):
            righe.append(c(r, TITOLO))
        else:
            righe.append(r)
    return "\n".join(righe)


# --------------------------------------------------------------------------
# Banner e cornici
# --------------------------------------------------------------------------

def pulisci_schermo():
    """Pulisce il terminale, se è un terminale vero."""
    if sys.stdout.isatty():
        os.system("clear" if os.name != "nt" else "cls")


def riga(carattere="="):
    print(c(carattere * LARGHEZZA, CORNICE))


def banner_righe():
    """Le righe del banner adatto al terminale: quello grande se entra, se no il compatto."""
    righe = BANNER.strip("\n").split("\n")
    try:
        BANNER.encode(sys.stdout.encoding or "ascii")
        entra = max(len(r) for r in righe) < shutil.get_terminal_size().columns
    except (UnicodeEncodeError, LookupError):
        entra = False
    return righe if entra else BANNER_PICCOLO.strip("\n").split("\n")


def banner_colorato(righe):
    """Il banner sfumato come la fiamma del drago, dal bianco al fucsia; i blocchi pieni
    prendono la sfumatura della riga, l'ombra a doppia linea un tono più scuro."""
    if not USA_COLORI:
        return "\n".join(righe)
    uscita = []
    for i, r in enumerate(righe):
        fiamma = FIAMMA[i * len(FIAMMA) // len(righe)]
        # spezza la riga in tratti omogenei: blocchi, ombra, spazi
        tratti = re.findall(r"█+|[╔╗╚╝║═]+|[^█╔╗╚╝║═]+", r)
        uscita.append("".join(
            c(s, OMBRA if s[0] in "╔╗╚╝║═" else fiamma)
            for s in tratti))
    return "\n".join(uscita)


def titolo_sezione(testo):
    riga()
    print(f"  {c(testo, TITOLO)}")
    riga()
    print()


def pausa():
    input(c("\nPremi Invio per tornare al menù... ", GRIGIO))


# --------------------------------------------------------------------------
# Domande e validazione
# --------------------------------------------------------------------------

def errore_input(messaggio):
    print(c(f"  [!] {messaggio}", AVVISO))


def avviso(*righe):
    """Avviso in rosso: la prima riga con [!], le altre allineate sotto."""
    for i, r in enumerate(righe):
        print(c(("[!] " if i == 0 else "    ") + r, AVVISO))


def valida_url(valore):
    if not valore or valore.startswith("-") or any(ch.isspace() for ch in valore):
        return "Inserisci un URL senza spazi che non inizi con '-' (es. https://esempio.it)."
    try:
        normalizza_url(valore)
    except ValueError:
        return "URL non valido: manca il nome dell'host (es. https://esempio.it)."
    return None


def chiedi(domanda, default="", valida=None):
    """Chiede un valore; con valida ripete la domanda finché il valore non è valido."""
    suffisso = " " + c(f"[{default}]", GRIGIO) if default else ""
    while True:
        risposta = input(f"{c(domanda, GRASSETTO)}{suffisso}: ").strip() or default
        errore = valida(risposta) if valida else None
        if not errore:
            return risposta
        errore_input(errore)


def chiedi_si_no(domanda, default=False):
    predefinito = "s/N" if not default else "S/n"
    righe = domanda.split("\n")   # le righe vuote iniziali restano fuori dal colore
    righe[-1] = c(righe[-1], GRASSETTO)
    risposta = input(f"{chr(10).join(righe)} {c(f'[{predefinito}]', GRIGIO)}: ").strip().lower()
    if not risposta:
        return default
    return risposta in ("s", "si", "sì", "y", "yes")


def chiedi_scelta(domanda, opzioni, default=0):
    """opzioni: lista di (etichetta, descrizione). Restituisce l'indice scelto."""
    print(c(domanda, GRASSETTO))
    for i, (etichetta, descrizione) in enumerate(opzioni, start=1):
        print(f"    {c(f'[{i}]', TITOLO)}  {etichetta}")
        if descrizione:
            print(f"         {c(descrizione, GRIGIO)}")
    while True:
        risposta = input(f"  Scelta {c(f'[{default + 1}]', GRIGIO)}: ").strip()
        if not risposta:
            return default
        if risposta.isdigit() and 1 <= int(risposta) <= len(opzioni):
            return int(risposta) - 1
        errore_input(f"Scegli un numero tra 1 e {len(opzioni)}.")


def mostra_opzioni(*opzioni):
    """Le opzioni della riga di comando che un passo imposta, come nella voce Opzioni."""
    for flag, descrizione in opzioni:
        print(f"  {c(f'{flag:<22}', ARANCIO)} {c(descrizione, GRIGIO)}")
    print()


class Passi:
    """Intestazioni numerate dei passi della scansione guidata.

    Il numero cresce a ogni passo mostrato: un passo saltato non lascia buchi."""

    def __init__(self):
        self.numero = 0

    def __call__(self, nome):
        self.numero += 1
        print("\n" + c(f"Passo {self.numero} - {nome}", TITOLO))
