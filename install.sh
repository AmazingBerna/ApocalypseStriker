#!/usr/bin/env bash
# install.sh - Prepara l'ambiente Python di ApocalypseStriker e installa il comando `apocalypse`.
#
#   ./install.sh
#
# Crea il virtualenv .venv, aggiorna pip, installa le dipendenze del progetto (se c'è un
# requirements.txt) e il pacchetto in modalità modificabile (pip install -e .). Dopo averlo
# eseguito e attivato il venv, è disponibile il comando `apocalypse attack`.
#
# Si occupa SOLO dell'ambiente Python: gli strumenti esterni (es. OWASP ZAP, usato dal
# penetration testing attivo) NON sono gestiti da questo script.
set -euo pipefail

# Radice del progetto = cartella di questo script (funziona da qualunque directory)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"

# 1. python3 presente?
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERRORE] python3 non trovato. Installa Python 3 e riprova." >&2
    echo "         Debian/Ubuntu/WSL:  sudo apt install python3 python3-venv" >&2
    exit 1
fi

# 2. virtualenv: crealo se manca; se c'è già, riusalo (idempotente)
if [ -x "$PY" ]; then
    echo "[i] Riuso il virtualenv esistente: $VENV"
elif [ -e "$VENV" ]; then
    # .venv esiste ma non è un venv Linux valido (manca .venv/bin/python): tipico se è
    # stato creato su Windows (ha .venv/Scripts/ invece di .venv/bin/).
    echo "[ERRORE] '$VENV' esiste ma non è un virtualenv Linux valido (manca $PY)." >&2
    echo "         Probabilmente è stato creato su Windows. Rimuovilo e rilancia:" >&2
    echo "             rm -rf \"$VENV\" && ./install.sh" >&2
    exit 1
else
    echo "[*] Creo il virtualenv in $VENV"
    python3 -m venv "$VENV"
fi

# 3. pip aggiornato
echo "[*] Aggiorno pip"
"$PY" -m pip install --upgrade pip

# 4. dipendenze del progetto (se c'è requirements.txt) + pacchetto in modalità modificabile
if [ -f "$ROOT/requirements.txt" ]; then
    echo "[*] Installo le dipendenze da requirements.txt"
    "$PY" -m pip install -r "$ROOT/requirements.txt"
else
    echo "[i] Nessun requirements.txt: il Vulnerability Assessment web usa solo la libreria standard."
fi
echo "[*] Installo ApocalypseStriker in modalità modificabile (pip install -e .)"
"$PY" -m pip install -e "$ROOT"

# 5. istruzioni finali
cat <<'EOF'

[OK] Ambiente pronto.

  Attiva il virtualenv:   source .venv/bin/activate
  Poi è disponibile:      apocalypse attack            (apre il menù)
                          apocalypse attack <url>      (scansione diretta)
  Verifica il PATH:       which apocalypse             (deve puntare dentro .venv)

Nota: gli strumenti esterni NON sono gestiti da questo script. In particolare OWASP ZAP
(usato dal penetration testing attivo) va installato a parte, oppure lo avvia il tool al
bisogno: install.sh prepara solo l'ambiente Python.
EOF
