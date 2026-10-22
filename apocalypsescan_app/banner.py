"""banner.py - Animazione ASCII a colori del drago (avvio, chiusura, Risveglio).

Due forme:

  CLASSICA   drago rosso a sette teste: sette funzioni, sette menti separate.
  RISVEGLIO  dopo aver divorato il nucleo del drago blu, il rosso diventa fucsia
             e le sette teste si fondono in una mente sola, disegnata in
             caratteri Braille (arte_braille.py). Le sette funzioni restano
             e si possono ancora eseguire separatamente, ma a leggerle e'
             un'unica mente.

Quale forma usare lo decide il file .risveglio: vedi risvegliato(),
segna_risveglio() e annulla_risveglio().

Uso:
    from apocalypsescan_app.banner import intro, outro, CLASSICA, RISVEGLIO

    intro()                       # forma del Risveglio (predefinita)
    intro(form=CLASSICA)          # forma storica
    outro(active_heads=[1, 2, 7])

Prova a schermo:
    python -m apocalypsescan_app.banner   # entrambe le forme e la trasformazione
"""

import os
import random
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

try:                                  # dentro al pacchetto
    from .arte_braille import DRAGO as DRAGO_BRAILLE, OCCHIO as OCCHIO_BRAILLE
except ImportError:                   # eseguito da solo: python banner.py
    from arte_braille import DRAGO as DRAGO_BRAILLE, OCCHIO as OCCHIO_BRAILLE

# --------------------------------------------------------------------------
# Stato del Risveglio
# --------------------------------------------------------------------------

# Il Risveglio avviene una volta sola per macchina, dal menù: questo file ricorda
# che c'è già stato. È escluso da git, così chi clona il progetto lo vede a sua volta.
MARCATORE = Path(__file__).resolve().parent.parent / ".risveglio"


def risvegliato():
    """True se su questa macchina il Risveglio è già avvenuto (Primal Version)."""
    return MARCATORE.exists()


def segna_risveglio():
    """Scrive il marcatore. False se la cartella non è scrivibile."""
    try:
        MARCATORE.write_text(datetime.now().isoformat(), encoding="utf-8")
        return True
    except OSError:
        return False


def annulla_risveglio():
    """Cancella il marcatore: si torna alla forma classica. False se non si può."""
    try:
        MARCATORE.unlink(missing_ok=True)
        return True
    except OSError:
        return False

# --------------------------------------------------------------------------
# Arte
# --------------------------------------------------------------------------

# Sette teste su sette colli: ogni etichetta [n] marca la testa n.
TESTE_SETTE = r"""
   [1]                                                         [7]
(\     /)    [2]                                     [6]    (\     /)
 \\___//  (\     /)    [3]                 [5]    (\     /)  \\___//
 / _ _ \   \\___//  (\     /)    [4]    (\     /)  \\___//   / _ _ \
|(o) (o)|  / _ _ \   \\___//  (\     /)  \\___//   / _ _ \  |(o) (o)|
 \  v  /  |(o) (o)|  / _ _ \   \\___//   / _ _ \  |(o) (o)|  \  v  /
  |. .|    \  v  /  |(o) (o)|  / _ _ \  |(o) (o)|  \  v  /    |. .|
  |VVV|     |. .|    \  v  /  |(o) (o)|  \  v  /    |. .|     |VVV|
   \^/      |VVV|     |. .|    \  v  /    |. .|     |VVV|      \^/
      \\     \^/      |VVV|     |. .|     |VVV|      \^/     //
         \\    \\      \^/      |VVV|      \^/      //    //
            \\    \\    \\       \^/       //    //    //
               \\   \\    \\     ||      //    //   //
                  \\  \\   \\    ||     //   //  //
                     \\  \\  \\  ||   //  //  //
                        \\ \\ \\ ||  // // //
"""

# Il corpo del drago classico, sotto le sette teste.
CORPO = r"""
    __                   _.-'''''''''''''-._                   __
   /  `-.__           .-'                   '-.           __.-'  \
  / /\     `'-.__   .'   A P O C A L Y P S E   '.   __.-''     /\ \
 / /  \   /\     `-/        S   C   A   N        \-'     /\   /  \ \
| /    \ /  \   /\|                               |/\   /  \ /    \ |
|/      \/   \ /  | /\/\/\/\/\/\/\/\/\/\/\/\/\/\  |  \ /   \/      \|
'             \/  | \/\/\/\/\/\/\/\/\/\/\/\/\/\/  |  \/             '
                  |  \/\/\/\/\/\/\/\/\/\/\/\/\/   |                   /\
                   \  \/\/\/\/\/\/\/\/\/\/\/\/   /                   <  >
                    '.                         .'                     \/
                     /`-._                 _.-'\                      /
                 ___/ /   `'-------------''   \ \___   `-._        _.'
                /_/_/_/                       \_\_\_\     `'--...--'
"""

SOTTOTITOLO = "·:·  A P O C A L Y P S E   S T R I K E R  ·:·"

LARGHEZZA = 79   # colonna oltre la quale la fiamma non si estende


def _componi(*blocchi):
    """Unisce i blocchi di arte in un'unica lista di righe."""
    return [riga for b in blocchi for riga in b.strip("\n").split("\n")]


# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------

RESET = "\033[0m"
TEETH = "\033[97m"
ASLEEP = "\033[38;5;240m"
BIANCO = "\033[1;38;5;231m"     # il culmine della luce e le scintille piu' vive


class Palette:
    """I colori di una forma. Codici ANSI a 256 colori."""

    def __init__(self, *, head, horn, neck, body, wing, scales,
                 title, eye, lit, fire, ramp=()):
        self.head = head        # cranio
        self.horn = horn        # corna
        self.neck = neck        # sfumatura del collo, dall'alto verso il basso
        self.body = body
        self.wing = wing
        self.scales = scales
        self.title = title      # lettere di APOCALYPSE SCAN nel petto
        self.eye = eye          # occhio aperto
        self.lit = lit          # funzione completata
        self.fire = fire        # fiamma, dal centro alla punta
        self.ramp = ramp        # sfumatura verticale, per le forme Braille


ROSSO = Palette(
    head="\033[38;5;160m",
    horn="\033[38;5;180m",
    neck=("\033[38;5;160m", "\033[38;5;160m", "\033[38;5;124m",
          "\033[38;5;124m", "\033[38;5;88m"),
    body="\033[38;5;88m",
    wing="\033[38;5;52m",
    scales="\033[38;5;130m",
    title="\033[1;38;5;220m",
    eye="\033[1;38;5;226m",
    lit="\033[1;38;5;46m",
    fire=("\033[38;5;226m", "\033[38;5;220m", "\033[38;5;214m",
          "\033[38;5;208m", "\033[38;5;202m", "\033[38;5;196m"),
)

# Fucsia: il colore di ApocalypseStriker, dal rosa chiaro brillante al magenta profondo.
FUCSIA = Palette(
    head="\033[38;5;200m",
    horn="\033[38;5;213m",
    neck=("\033[38;5;213m", "\033[38;5;206m", "\033[38;5;200m",
          "\033[38;5;164m", "\033[38;5;90m"),
    body="\033[38;5;90m",
    wing="\033[38;5;53m",
    scales="\033[38;5;169m",
    title="\033[1;38;5;206m",
    eye="\033[1;38;5;219m",
    lit="\033[1;38;5;219m",
    fire=("\033[38;5;231m", "\033[38;5;225m", "\033[38;5;219m",
          "\033[38;5;213m", "\033[38;5;207m", "\033[38;5;201m"),
    ramp=("\033[38;5;219m", "\033[38;5;213m", "\033[38;5;207m",
          "\033[38;5;206m", "\033[38;5;200m", "\033[38;5;164m",
          "\033[38;5;127m", "\033[38;5;90m"),
)


# --------------------------------------------------------------------------
# Forme
# --------------------------------------------------------------------------

class Form:
    """Una forma del drago: arte, palette e geometria delle teste."""

    def __init__(self, *, name, lines, palette, heads=None, eyes_row=-1,
                 teeth_row=-1, horn_rows=(), fire_from=(0, 0), labelled=False,
                 subtitle=None, eye_char="o", braille=False, eye_cells=(),
                 body_top=16, chest=range(18, 51)):
        self.name = name
        self.lines = lines
        self.palette = palette
        self.heads = heads or {}        # n -> (riga, colonna, altezza, larghezza)
        self.braille = braille          # True: si colora per fasce, non per regione
        self.eyes_row = eyes_row        # righe relative alla cima della testa
        self.teeth_row = teeth_row
        self.horn_rows = horn_rows
        self.eye_char = eye_char        # carattere dell'occhio aperto nell'arte
        self.eye_cells = set(eye_cells)   # Braille: celle (riga, colonna) dell'occhio
        self.labelled = labelled        # True se la riga 0 di ogni testa e' l'etichetta [n]
        self.subtitle = subtitle
        self.fire_row, self.fire_col = fire_from
        self.fire_max = LARGHEZZA - self.fire_col
        self.body_top = body_top
        self.chest = chest
        self.wing_rows = range(body_top, body_top + 7)
        self.scale_rows = range(body_top + 5, body_top + 9)

    def head_at(self, row, col):
        """(testa, riga relativa alla cima) se la cella cade dentro una testa."""
        for head, (r, c, h, w) in self.heads.items():
            if r <= row < r + h and c <= col < c + w:
                return head, row - r
        return None, None


def _teste_da_etichette(lines, altezza):
    """Ricava le sette teste dalle etichette [n] presenti nell'arte."""
    etichette = {int(m.group(1)): (row, m.start())
                 for row, line in enumerate(lines)
                 for m in re.finditer(r"\[(\d)\]", line)}
    heads = {n: (r, c - 3, altezza + 1, 9) for n, (r, c) in etichette.items()}
    return heads, etichette


_LINEE_SETTE = _componi(TESTE_SETTE, CORPO)
_HEADS_SETTE, _ETICHETTE = _teste_da_etichette(_LINEE_SETTE, 8)

CLASSICA = Form(
    name="classica",
    lines=_LINEE_SETTE,
    palette=ROSSO,
    heads=_HEADS_SETTE,
    eyes_row=4,
    teeth_row=7,
    horn_rows=(1, 2),
    labelled=True,
    # la fiamma esce dalla bocca della testa 7, verso destra
    fire_from=(_ETICHETTE[7][0] + 7, _ETICHETTE[7][1] + 4),
)

# Il Risveglio: la mente unica disegnata in Braille.
# Il corpo si anima per fasce orizzontali; l'unica parte indirizzabile e'
# l'occhio, che si apre e si chiude in ciano.
RISVEGLIO = Form(
    name="risveglio",
    lines=DRAGO_BRAILLE.strip("\n").split("\n"),
    palette=FUCSIA,
    braille=True,
    eye_cells=OCCHIO_BRAILLE,
    subtitle=SOTTOTITOLO,
)


def entra(form):
    """True se il terminale e' abbastanza grande da ridisegnare la forma sul posto.

    Il ridisegno in posizione risale di tante righe quante ne ha il disegno:
    se il terminale e' piu' corto, il cursore finisce fuori dall'area visibile
    e l'animazione si rompe. Lo stesso se e' piu' stretto: le righe vanno a
    capo e occupano piu' spazio del previsto. In quel caso il drago si stampa
    fermo.
    """
    dimensioni = shutil.get_terminal_size(fallback=(80, 24))
    alto = len(form.lines) + 4
    largo = max(len(riga) for riga in form.lines)
    return dimensioni.lines >= alto and dimensioni.columns >= largo


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _enabled(stream):
    if not stream.isatty() or os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")   # abilita le sequenze ANSI nella console di Windows
    return True


def _flame(form, size):
    """Fiamma a cono: riga centrale piena, righe sopra e sotto piu' corte."""
    if not size:
        return {}
    flame = {form.fire_row: "~" * (size - 1) + ">"}
    if size >= 4:
        flame[form.fire_row - 1] = " ." + "~" * (size - 4) + "-"
        flame[form.fire_row + 1] = " '" + "~" * (size - 4) + "-"
    return flame


def _char_color(form, row, col, ch, eyes_open, lit, asleep):
    p = form.palette
    head, offset = form.head_at(row, col)

    if head and form.labelled and offset == 0:
        return p.lit if head in lit else ASLEEP

    if head:
        if head in asleep:
            return ASLEEP
        if offset == form.eyes_row and ch in (form.eye_char, "-"):
            return p.eye if eyes_open else ASLEEP
        if offset >= form.teeth_row and ch in "V^":
            return TEETH
        if head in lit:
            return p.lit
        return p.horn if offset in form.horn_rows else p.head

    if row < form.body_top:
        return p.neck[max(0, len(p.neck) - (form.body_top - row))]
    if ch.isalpha():
        return p.title
    if row in form.scale_rows and col in form.chest:
        return p.scales
    if row in form.wing_rows and col not in form.chest:
        return p.wing
    return p.body


def _frame_braille(form, rows, glow_row=None, luce=0, scintille=None,
                   eyes_open=True):
    """Colora il Braille per fasce orizzontali: una sfumatura verticale, piu'
    un'onda luminosa centrata su glow_row quando passa.

    luce schiarisce tutte le fasce di altrettanti gradini della sfumatura:
    oltre il gradino piu' chiaro il corpo diventa bianco.
    scintille e' {riga: [(colonna, colore), ...]}: singoli punti accesi.
    Le celle di form.eye_cells prendono il colore dell'occhio (grigio se
    chiuso), sopra fasce, onda e scintille.
    """
    ramp = form.palette.ramp
    occhio = form.palette.eye if eyes_open else ASLEEP
    totale = len(form.lines)
    out = []
    for row, text in enumerate(form.lines[:rows]):
        gradino = row * len(ramp) // totale - luce
        colore = ramp[gradino] if gradino >= 0 else BIANCO
        if glow_row is not None:
            distanza = abs(row - glow_row)
            if distanza == 0:
                colore = form.palette.eye       # cresta dell'onda, ciano
            elif distanza <= 2:
                colore = ramp[0]
        accese = dict(scintille.get(row, ())) if scintille else {}
        accese.update((c, occhio) for r, c in form.eye_cells
                      if r == row and c < len(text))
        if accese:
            pezzi, prima = [], 0
            for col, acceso in sorted(accese.items()):
                # RESET prima di riprendere la fascia: toglie il grassetto
                pezzi += [text[prima:col], acceso, text[col], RESET + colore]
                prima = col + 1
            pezzi.append(text[prima:])
            text = "".join(pezzi)
        out.append(colore + text + RESET)
    return out


def _celle_piene(form):
    """Le posizioni dei caratteri Braille con almeno un punto acceso."""
    return [(row, col) for row, line in enumerate(form.lines)
            for col, ch in enumerate(line) if ch not in " ⠀"]


def _scintille(celle, quante, colori, rng):
    """Sceglie a caso quante celle far brillare, ognuna di uno dei colori."""
    scelte = {}
    for row, col in rng.sample(celle, min(quante, len(celle))):
        scelte.setdefault(row, []).append((col, rng.choice(colori)))
    return scelte


def _frame(form, rows, eyes_open=True, fire=0, lit=(), asleep=(), glow_row=None,
           luce=0, scintille=None):
    """Costruisce le righe colorate del drago nello stato richiesto."""
    if form.braille:
        return _frame_braille(form, rows, glow_row, luce, scintille, eyes_open)
    p = form.palette
    flame = _flame(form, fire)
    lines = []
    for row, text in enumerate(form.lines[:rows]):
        flame_at = len(text)
        if row in flame:
            text = text.ljust(form.fire_col)[:form.fire_col] + flame[row]
            flame_at = form.fire_col
        out, current = [], None
        for col, ch in enumerate(text):
            if col >= flame_at:
                color = p.fire[(col - form.fire_col) * len(p.fire) // form.fire_max]
            else:
                head, offset = form.head_at(row, col)
                if offset == form.eyes_row and ch == form.eye_char and (not eyes_open or head in asleep):
                    ch = "-"
                color = None if ch == " " else _char_color(
                    form, row, col, ch, eyes_open, lit, asleep)
            if color and color != current:
                out.append(color)
                current = color
            out.append(ch)
        lines.append("".join(out) + RESET)
    return lines


class _Screen:
    """Ridisegna il drago sempre nella stessa area del terminale."""

    def __init__(self, stream):
        self.stream = stream
        self.drawn = 0

    def draw(self, lines, pause=0.0):
        if self.drawn:
            self.stream.write(f"\033[{self.drawn}F")
        for line in lines:
            self.stream.write("\033[K" + line + "\n")
        self.drawn = len(lines)
        self.stream.flush()
        if pause:
            time.sleep(pause)


def _animate(scene, stream):
    stream.write("\033[?25l")   # nasconde il cursore
    try:
        scene(_Screen(stream))
    except KeyboardInterrupt:
        stream.write(RESET + "\n")
        raise
    finally:
        stream.write(RESET + "\033[?25h")
        stream.flush()


# --------------------------------------------------------------------------
# Scene
# --------------------------------------------------------------------------

def _scritte_intro(form, stream):
    """Sottotitolo e motto sotto il drago, alla fine dell'avvio."""
    p = form.palette
    if form.subtitle:
        stream.write(f"\n{' ' * 7}{p.eye}{form.subtitle}{RESET}\n")
    stream.write(f"\n   {p.title}VAPT di applicazioni web{RESET}"
                 f"  {ASLEEP}Vulnerability Assessment + Penetration Testing{RESET}\n\n")


def _fermo(form, stream):
    """Stampa la forma intera una volta sola, senza ridisegnarla."""
    stream.write("\n" + "\n".join(_frame(form, len(form.lines))) + "\n")
    stream.flush()


def intro(form=None, stream=sys.stdout):
    """Il drago emerge, apre gli occhi e sputa fuoco.

    Con form=None mostra la forma del Risveglio. Nella forma Braille il drago
    emerge a occhio chiuso, l'occhio si apre in ciano e poi un'onda di luce
    risale il corpo. Se il terminale e' troppo basso o troppo stretto per
    animarlo, il drago Braille compare fermo.
    """
    if not _enabled(stream):
        return
    if form is None:
        form = RISVEGLIO

    if form.braille:
        if not entra(form):
            _fermo(form, stream)
            _scritte_intro(form, stream)
            return

        def scena_braille(screen):
            stream.write("\n")
            for rows in range(1, len(form.lines) + 1, 2):
                screen.draw(_frame(form, rows, eyes_open=False), 0.015)
            screen.draw(_frame(form, len(form.lines), eyes_open=False), 0.25)
            for eyes_open in (True, False, True):
                screen.draw(_frame(form, len(form.lines), eyes_open=eyes_open), 0.15)
            for g in range(len(form.lines) - 1, -3, -2):      # l'onda risale
                screen.draw(_frame(form, len(form.lines), glow_row=g), 0.02)
            screen.draw(_frame(form, len(form.lines)), 0.2)
            _scritte_intro(form, stream)
            time.sleep(0.4)

        _animate(scena_braille, stream)
        return

    def scene(screen):
        stream.write("\n")
        for rows in range(1, len(form.lines) + 1):
            screen.draw(_frame(form, rows, eyes_open=False), 0.04)
        time.sleep(0.3)
        for eyes_open in (True, False, True):
            screen.draw(_frame(form, len(form.lines), eyes_open=eyes_open), 0.15)
        for fire in range(1, form.fire_max + 1):
            screen.draw(_frame(form, len(form.lines), fire=fire), 0.03)
        _scritte_intro(form, stream)
        time.sleep(0.4)

    _animate(scene, stream)


def outro(active_heads=range(1, 8), form=None, stream=sys.stdout):
    """Le funzioni eseguite si accendono una alla volta, poi il drago riposa.

    Nella forma classica ogni testa si illumina per conto suo e le funzioni
    saltate restano grigie. Nel Risveglio (form=None) un'onda di luce risale
    il corpo tanto piu' in alto quante piu' funzioni sono state completate.
    """
    if not _enabled(stream):
        return
    if form is None:
        form = RISVEGLIO
    p = form.palette
    attive = sorted(set(active_heads))
    total = len(attive)

    if form.braille:
        alte = len(form.lines)
        # l'onda risale di una frazione del corpo pari alle funzioni svolte
        meta = alte - int(alte * total / 7)
        messaggio = (f"\n   {p.lit}Scansione completata: {total} funzioni su 7 "
                     f"hanno nutrito la mente. Il drago riposa.{RESET}\n\n")
        if not entra(form):
            _fermo(form, stream)
            stream.write(messaggio)
            return

        def scena_braille(screen):
            stream.write("\n")
            screen.draw(_frame(form, alte), 0.3)
            for g in range(alte - 1, meta - 1, -2):
                screen.draw(_frame(form, alte, glow_row=g), 0.02)
            for _ in range(3):
                screen.draw(_frame(form, alte, glow_row=meta), 0.12)
                screen.draw(_frame(form, alte), 0.12)
            stream.write(messaggio)

        _animate(scena_braille, stream)
        return

    passi = [set(attive[:n + 1]) for n in range(len(attive))]
    asleep = set(form.heads) - set(attive)

    def scene(screen):
        stream.write("\n")
        screen.draw(_frame(form, len(form.lines), asleep=asleep), 0.3)
        lit = set()
        for lit in passi:
            screen.draw(_frame(form, len(form.lines), lit=lit, asleep=asleep), 0.18)
        for _ in range(2):
            for fire in range(1, form.fire_max + 1, 2):
                screen.draw(_frame(form, len(form.lines), fire=fire,
                                   lit=lit, asleep=asleep), 0.025)
        for fire in range(form.fire_max, -1, -2):
            screen.draw(_frame(form, len(form.lines), fire=fire,
                               lit=lit, asleep=asleep), 0.03)
        screen.draw(_frame(form, len(form.lines), eyes_open=False,
                           lit=lit, asleep=asleep), 0.2)
        stream.write(f"\n   {p.lit}Scansione completata: {total} teste su 7 "
                     f"hanno lavorato. Il drago riposa.{RESET}\n\n")

    _animate(scene, stream)


def trasformazione(stream=sys.stdout):
    """Il Risveglio Primordiale: il drago rosso divora il nucleo blu.

    Le sette teste si spengono una alla volta, un lampo ciano attraversa il
    corpo, e dal buio risale il drago Braille fucsia, la mente unica: le scaglie
    luccicano al passaggio del nucleo, poi tutto il corpo si illumina fino al
    bianco e ricade nel fucsia.
    Restituisce True solo se l'animazione è stata mostrata davvero.
    """
    if not _enabled(stream):
        return False

    vecchia, nuova = CLASSICA, RISVEGLIO
    p = nuova.palette

    def scena(screen):
        stream.write("\n")
        tutte = set(vecchia.heads)

        # 1. il drago rosso, desto
        screen.draw(_frame(vecchia, len(vecchia.lines), lit=tutte), 0.7)

        # 2. le teste si spengono, dalla settima alla prima
        for n in range(7, 0, -1):
            spente = {h for h in tutte if h >= n}
            screen.draw(_frame(vecchia, len(vecchia.lines), asleep=spente), 0.16)
        screen.draw(_frame(vecchia, len(vecchia.lines),
                           eyes_open=False, asleep=tutte), 0.5)

        # 3. il lampo del nucleo
        lampo = [p.eye + riga + RESET for riga in vecchia.lines]
        for _ in range(2):
            screen.draw(lampo, 0.09)
            screen.draw(_frame(vecchia, len(vecchia.lines),
                               eyes_open=False, asleep=tutte), 0.09)
        screen.draw(lampo, 0.15)

        # 4. il buio
        screen.draw([""] * len(vecchia.lines), 0.45)

        # 5-7 solo se il terminale e' abbastanza alto da ridisegnare il Braille sul posto
        alte = len(nuova.lines)
        if entra(nuova):
            rng = random.Random()
            celle = _celle_piene(nuova)
            colori = (BIANCO, p.eye, p.title)     # bianco, ciano del nucleo, rosa

            # 5. la mente unica risale dal buio
            for rows in range(1, alte + 1, 2):
                screen.draw(_frame(nuova, rows), 0.03)

            # 6. il nucleo la attraversa dal basso e le scaglie luccicano al suo passaggio
            for g in range(alte - 1, -3, -2):
                screen.draw(_frame(nuova, alte, glow_row=g,
                                   scintille=_scintille(celle, 70, colori, rng)), 0.045)

            # 7. la mente si accende: la luce sale fino al bianco e ricade nel fucsia
            gradini = len(p.ramp) + 1
            for luce in [*range(1, gradini + 1), *range(gradini - 1, -1, -1)]:
                screen.draw(_frame(nuova, alte, luce=luce), 0.04)

            # 8. le ultime scintille si spengono
            for quante in range(60, 0, -6):
                screen.draw(_frame(nuova, alte,
                                   scintille=_scintille(celle, quante, colori, rng)), 0.06)
        # l'ultimo disegno non viene piu' ridisegnato: puo' scorrere anche
        # oltre l'altezza del terminale
        screen.draw(_frame(nuova, alte), 0.4)

        if nuova.subtitle:
            stream.write(f"\n{' ' * 7}{p.eye}{nuova.subtitle}{RESET}\n\n")
        time.sleep(0.5)

    _animate(scena, stream)
    return True


def ritratto(form=RISVEGLIO, stream=sys.stdout):
    """Stampa il drago fermo, in testo puro: per quando i colori sono spenti
    e l'animazione non c'e'."""
    try:
        stream.write("\n" + "\n".join(form.lines) + "\n")
        if form.subtitle:
            stream.write(f"\n{' ' * 7}{form.subtitle}\n")
        stream.write("\n")
    except UnicodeEncodeError:    # console senza i caratteri Braille
        stream.write(f"\n{form.subtitle or ''}\n\n")
    stream.flush()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Prova le forme del drago.")
    ap.add_argument("scena", nargs="?", default="tutto",
                    choices=["tutto", "classica", "risveglio", "trasformazione"])
    scelta = ap.parse_args().scena

    if scelta in ("tutto", "classica"):
        intro(form=CLASSICA)
        outro(active_heads=[1, 2, 3, 5, 7], form=CLASSICA)
    if scelta in ("tutto", "risveglio"):
        intro()
        outro(active_heads=[1, 2, 3, 5, 7])
    if scelta in ("tutto", "trasformazione"):
        trasformazione()
