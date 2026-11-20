"""riservatezza.py - Il secondo filtro: nessun segreto in report, log o terminale.

Il primo filtro è il modo in cui i raccoglitori lavorano (le password viaggiano su stdin, i
frammenti di codice di Bandit vengono scartati, dei file sensibili si leggono solo nome e
permessi). Questo modulo è la rete di sicurezza: oscura() viene applicato a OGNI finding e a
ogni messaggio di stato prima che escano dall'analisi interna.

Toglie:
1. i valori segreti noti (password di DB e di sudo, letti dalle variabili d'ambiente);
2. i valori dopo nomi come password=, TOKEN="...", "secret": "...", IDENTIFIED BY '...'
   (dopo i due punti solo se il valore è tra virgolette, per non toccare il testo normale);
3. i blocchi di chiavi private (-----BEGIN ... PRIVATE KEY-----).
Il NOME del segreto resta visibile (es. "password=***"): serve a sapere cosa correggere.
"""
import re

MASCHERA = "***"

_NOME_SEGRETO = (r"[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|"
                 r"private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*")
# nome=valore, NOME="valore", password = 'x'  (stile config, env, codice)
_UGUALE = re.compile(rf"(?i)\b({_NOME_SEGRETO})(['\"]?\s*=\s*)(['\"]?)([^\s'\",;]+)\3")
# "nome": "valore", nome: 'valore'  (JSON, YAML, testo di Bandit): solo valori TRA VIRGOLETTE,
# così una frase come "senza password: chiunque..." resta intatta
_DUE_PUNTI = re.compile(rf"(?i)\b({_NOME_SEGRETO})(['\"]?\s*:\s*)(['\"])([^'\"]+)\3")
_IDENTIFIED_BY = re.compile(r"(?i)(identified\s+by\s+(?:password\s+)?)(['\"])(.*?)\2")
_CHIAVE_PRIVATA = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)


def _assegnazione(m):
    nome, sep, virgolette, _valore = m.groups()
    return f"{nome}{sep}{virgolette}{MASCHERA}{virgolette}"


def oscura(testo, segreti=()):
    """Restituisce testo con i segreti sostituiti da ***. segreti: valori noti da togliere."""
    if not isinstance(testo, str) or not testo:
        return testo
    for s in sorted((s for s in segreti if s and len(s) >= 3), key=len, reverse=True):
        testo = testo.replace(s, MASCHERA)
    testo = _CHIAVE_PRIVATA.sub("[chiave privata omessa]", testo)
    testo = _IDENTIFIED_BY.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASCHERA}{m.group(2)}", testo)
    testo = _UGUALE.sub(_assegnazione, testo)
    return _DUE_PUNTI.sub(_assegnazione, testo)


def oscura_valore(valore, segreti=()):
    """oscura() applicato in profondità a stringhe, liste, tuple e dizionari."""
    if isinstance(valore, str):
        return oscura(valore, segreti)
    if isinstance(valore, dict):
        return {k: oscura_valore(v, segreti) for k, v in valore.items()}
    if isinstance(valore, (list, tuple)):
        return type(valore)(oscura_valore(v, segreti) for v in valore)
    return valore
