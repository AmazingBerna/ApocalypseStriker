"""progress.py - Barra di avanzamento sulle fasi del programma."""

import os
import shutil
import sys
import threading
import time

# Peso di ogni fase, proporzionale alla durata tipica osservata.
PHASE_WEIGHTS = {
    "threat_intel": 1,
    "system_info": 1,
    "firewall": 1,
    "nmap": 3,
    "nmap_udp": 4,
    "services": 1,
    "ssh_audit": 1,
    "trivy": 25,
    "lynis": 18,
    "report": 1,
    # VAPT web (ApocalypseStriker): recon = 4 handshake TLS + GET; cve = una richiesta NVD
    # (~7 s senza chiave) per ogni tecnologia con versione
    "web_recon": 2,
    "web_cve": 2,
}

RESET = "\033[0m"
GRASSETTO = "\033[1m"
GRIGIO = "\033[38;5;245m"
VUOTO = "\033[38;5;238m"           # la parte della barra ancora da riempire
VERDE = "\033[1;38;5;46m"
ROSSO = "\033[1;38;5;196m"
ORO = "\033[1;38;5;220m"
# La sfumatura della fiamma del drago, dal giallo al rosso lungo la barra
FIAMMA = ("\033[38;5;226m", "\033[38;5;220m", "\033[38;5;214m",
          "\033[38;5;208m", "\033[38;5;202m", "\033[38;5;196m")

# Caratteri grafici, con il ripiego ASCII per le console che non li supportano
SIMBOLI_UNICODE = {"pieno": "█", "vuoto": "░", "parziali": "▏▎▍▌▋▊▉",
                   "spinner": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "ok": "✔", "errore": "✘"}
SIMBOLI_ASCII = {"pieno": "#", "vuoto": "-", "parziali": "",
                 "spinner": "|/-\\", "ok": "OK", "errore": "!!"}


def _simboli(stream):
    simboli = SIMBOLI_UNICODE
    try:
        "".join(v for v in simboli.values()).encode(stream.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        simboli = SIMBOLI_ASCII
    return simboli


def _colori_attivi(stream):
    if not stream.isatty() or os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")   # abilita le sequenze ANSI nella console di Windows
    return True


def _mmss(secs):
    secs = int(secs)
    return f"{secs // 60:02d}:{secs % 60:02d}"


class ProgressTracker:
    """Barra di avanzamento basata sulle fasi completate."""

    def __init__(self, phases, width=40, stream=sys.stdout):
        self.total = sum(PHASE_WEIGHTS.get(p, 1) for p in phases)
        self.done = 0
        self.width = width
        self.stream = stream
        self.enabled = stream.isatty()   # disattiva se l'output va su file
        self.colori = _colori_attivi(stream)
        self.simboli = _simboli(stream)
        self.label = ""
        self.phase_start = None
        self.started = None
        self.completed = []    # (etichetta, ok, secondi) di ogni fase conclusa
        self._phase = None
        self._frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def _c(self, testo, colore):
        return f"{colore}{testo}{RESET}" if self.colori and testo else testo

    def _percent(self):
        return 100.0 * self.done / self.total if self.total else 100.0

    def elapsed(self):
        """Secondi trascorsi dall'avvio della barra."""
        return time.time() - self.started if self.started else 0

    @property
    def failed(self):
        return [label for label, ok, _ in self.completed if not ok]

    def _bar(self):
        """La barra: blocchi pieni sfumati, un blocco parziale, poi il vuoto."""
        s = self.simboli
        ottavi = int(self.width * 8 * self._percent() / 100)
        pieni, resto = divmod(ottavi, 8)
        celle = [self._c(s["pieno"], FIAMMA[i * len(FIAMMA) // self.width])
                 for i in range(pieni)]
        if pieni < self.width:
            parziale = s["parziali"][resto - 1] if resto and s["parziali"] else ""
            if parziale:
                celle.append(self._c(parziale, FIAMMA[pieni * len(FIAMMA) // self.width]))
            celle.append(self._c(s["vuoto"] * (self.width - len(celle)), VUOTO))
        return "".join(celle)

    def _clear(self):
        colonne = shutil.get_terminal_size().columns
        self.stream.write("\r" + " " * (colonne - 1) + "\r")

    def _render(self):
        with self._lock:
            spinner = ""
            tempo = ""
            if self.phase_start:
                giri = self.simboli["spinner"]
                spinner = self._c(giri[self._frame % len(giri)], ORO) + " "
                tempo = self._c(f" {_mmss(time.time() - self.phase_start)}", GRIGIO)
            self._clear()
            self.stream.write(f"  {self._bar()} {self._c(f'{self._percent():5.1f}%', GRASSETTO)}"
                              f"  {spinner}{self.label}{tempo}")
            self.stream.flush()

    def _tick(self):
        while not self._stop.wait(0.15):
            if self.phase_start:
                self._frame += 1
                self._render()

    def start(self):
        global _active
        _active = self
        self.started = time.time()
        if self.enabled:
            self._thread = threading.Thread(target=self._tick, daemon=True)
            self._thread.start()

    def begin(self, phase, label):
        self._phase = phase
        self.label = label
        self.phase_start = time.time()
        if self.enabled:
            self._render()
        else:
            print(f"[*] {label}...")

    def end(self, ok=True):
        self.done += PHASE_WEIGHTS.get(self._phase, 1)
        secs = time.time() - self.phase_start if self.phase_start else 0
        self.phase_start = None
        self.completed.append((self.label, ok, secs))
        if self.enabled:
            simbolo = self._c(self.simboli["ok"], VERDE) if ok else \
                self._c(self.simboli["errore"], ROSSO)
            with self._lock:
                self._clear()
                self.stream.write(f"  {simbolo} {self.label:<40}"
                                  f"{self._c(_mmss(secs), GRIGIO)}\n")
            self.label = ""   # fase chiusa: la barra resta senza etichetta fino alla prossima
            self._render()
        else:
            print(f"[{'OK' if ok else 'errore'}] {self.label} - {int(secs)}s")

    def finish(self):
        """Chiude la barra. Chiamare anche prima di ogni uscita anticipata."""
        global _active
        self._stop.set()
        if self._thread:
            self._thread.join()
        self.done = self.total
        if self.enabled:
            self.label = self._c("completato", VERDE)
            self.phase_start = None
            self._render()
            self.stream.write("\n")
        _active = None


_active = None   # tracker attivo: impostato da start(), azzerato da finish()


def log(message):
    """Stampa un messaggio senza rovinare la riga della barra."""
    tracker = _active
    if tracker is None or not tracker.enabled:
        print(message)
        return
    with tracker._lock:
        tracker._clear()
        tracker.stream.write(message + "\n")
    tracker._render()
