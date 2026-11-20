"""webserver.py - Configurazione del web server (nginx, Apache) letta dall'interno.

nginx: `nginx -T` stampa la configurazione completa; Apache: `grep` estrae dalle cartelle di
configurazione SOLO le direttive che interessano (ServerTokens, ServerSignature, SSLProtocol,
Header, TraceEnable). In entrambi i casi la configurazione grezza NON viene salvata: se ne
ricavano poche direttive e i finding citano solo quelle.

Controlli: versione dichiarata (server_tokens / ServerTokens), versioni di TLS obsolete,
header di sicurezza non impostati, TRACE e ServerSignature (Apache).
"""
import re

from ..config import (INT_WS_HEADER, INT_WS_HEADER_ATTESI, INT_WS_SIGNATURE, INT_WS_TLS_VECCHIO,
                      INT_WS_TRACE, INT_WS_VERSIONE)
from .comune import (ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, finding_interno, info_interno,
                     prima_riga, stato)

PROTOCOLLI_VECCHI = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _senza_commenti(testo):
    return "\n".join(riga.split("#", 1)[0] for riga in (testo or "").splitlines())


# ==========================================================================
# nginx
# ==========================================================================

def analizza_nginx(config):
    """Direttive rilevanti dall'output di `nginx -T` (senza commenti)."""
    testo = _senza_commenti(config)
    tokens = [v.lower() for v in re.findall(r"\bserver_tokens\s+(\w+)\s*;", testo)]
    protocolli = set()
    for valore in re.findall(r"\bssl_protocols\s+([^;]+);", testo):
        protocolli.update(valore.split())
    header = {h.lower() for h in re.findall(r"\badd_header\s+['\"]?([A-Za-z0-9-]+)", testo)}
    return {"server_tokens": tokens, "ssl_protocols": sorted(protocolli), "header": sorted(header)}


def _finding_nginx(d):
    findings = []
    # il default di nginx è "on": senza una direttiva "off" la versione viene dichiarata
    if not d["server_tokens"] or any(t != "off" for t in d["server_tokens"]):
        valore = ", ".join(d["server_tokens"]) or "assente (default on)"
        findings.append(finding_interno(
            "webserver", "nginx dichiara la versione (server_tokens)", INT_WS_VERSIONE,
            elemento="nginx: server_tokens", evidence=f"server_tokens {valore}", key="nginx-tokens"))
    vecchi = [p for p in d["ssl_protocols"] if p in PROTOCOLLI_VECCHI]
    if vecchi:
        findings.append(finding_interno(
            "webserver", f"nginx abilita TLS obsoleto: {', '.join(vecchi)}", INT_WS_TLS_VECCHIO,
            elemento="nginx: ssl_protocols", evidence=f"ssl_protocols {' '.join(d['ssl_protocols'])}",
            key="nginx-tls"))
    mancanti = [h for h in INT_WS_HEADER_ATTESI if h not in d["header"]]
    if mancanti:
        findings.append(finding_interno(
            "webserver", f"nginx non imposta {len(mancanti)} header di sicurezza", INT_WS_HEADER,
            elemento="nginx: add_header", evidence="mancano: " + ", ".join(mancanti),
            key="nginx-header"))
    return findings


def _nginx(esecutore):
    findings, note = [], []
    r, errore = esegui(esecutore, ["nginx", "-v"], timeout=30)
    if not errore:
        m = re.search(r"nginx/(\S+)(?:\s+\(([^)]+)\))?", (r.stderr or "") + (r.stdout or ""))
        if m:
            findings.append(info_interno("webserver", f"nginx {m.group(1)}",
                                         f"Versione di nginx installata: {m.group(0)}.",
                                         elemento="nginx", key="nginx-versione"))
    r, errore = esegui(esecutore, ["nginx", "-T"], sudo=True, timeout=60)
    if errore or r.returncode != 0 or "server" not in (r.stdout or ""):
        motivo = errore or prima_riga(r.stderr) or "configurazione non leggibile"
        note.append(f"nginx -T non riuscito ({motivo}; di norma serve sudo)")
        return findings, note
    findings += _finding_nginx(analizza_nginx(r.stdout))
    return findings, note


# ==========================================================================
# Apache
# ==========================================================================

def analizza_apache(righe):
    """Direttive rilevanti dalle righe estratte con grep."""
    d = {"ServerTokens": [], "ServerSignature": [], "SSLProtocol": [], "TraceEnable": [], "header": set()}
    for riga in (righe or "").splitlines():
        riga = riga.strip()
        m = re.match(r"(?i)(ServerTokens|ServerSignature|SSLProtocol|TraceEnable)\s+(.+)$", riga)
        if m:
            chiave = {k.lower(): k for k in d}[m.group(1).lower()]
            d[chiave].append(m.group(2).strip())
            continue
        m = re.match(r"(?i)Header\s+(?:always\s+)?(?:set|append|add|merge|setifempty)\s+['\"]?([A-Za-z0-9-]+)", riga)
        if m:
            d["header"].add(m.group(1).lower())
    d["header"] = sorted(d["header"])
    return d


def _protocolli_apache(valori):
    abilitati = set()
    for valore in valori:
        for token in valore.split():
            nome = token.lstrip("+-")
            gruppo = ({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"} if nome.lower() == "all" else {nome})
            if token.startswith("-"):
                abilitati -= gruppo
            else:
                abilitati |= gruppo
    return sorted(p for p in abilitati if p in PROTOCOLLI_VECCHI)


def _finding_apache(d):
    findings = []
    ultimo = (d["ServerTokens"] or ["Full (default)"])[-1]
    if ultimo.lower() not in ("prod", "productonly"):
        findings.append(finding_interno(
            "webserver", "Apache dichiara la versione (ServerTokens)", INT_WS_VERSIONE,
            elemento="apache: ServerTokens", evidence=f"ServerTokens {ultimo}", key="apache-tokens"))
    if d["ServerSignature"] and d["ServerSignature"][-1].lower() != "off":
        findings.append(finding_interno(
            "webserver", "Apache: ServerSignature attivo", INT_WS_SIGNATURE,
            elemento="apache: ServerSignature", evidence=f"ServerSignature {d['ServerSignature'][-1]}",
            key="apache-signature"))
    if not d["TraceEnable"] or d["TraceEnable"][-1].lower() != "off":
        valore = d["TraceEnable"][-1] if d["TraceEnable"] else "assente (default On)"
        findings.append(finding_interno(
            "webserver", "Apache: metodo TRACE abilitato", INT_WS_TRACE,
            elemento="apache: TraceEnable", evidence=f"TraceEnable {valore}", key="apache-trace"))
    vecchi = _protocolli_apache(d["SSLProtocol"])
    if vecchi:
        findings.append(finding_interno(
            "webserver", f"Apache abilita TLS obsoleto: {', '.join(vecchi)}", INT_WS_TLS_VECCHIO,
            elemento="apache: SSLProtocol", evidence="SSLProtocol " + " / ".join(d["SSLProtocol"]),
            key="apache-tls"))
    mancanti = [h for h in INT_WS_HEADER_ATTESI if h not in d["header"]]
    if mancanti:
        findings.append(finding_interno(
            "webserver", f"Apache non imposta {len(mancanti)} header di sicurezza", INT_WS_HEADER,
            elemento="apache: Header", evidence="mancano: " + ", ".join(mancanti), key="apache-header"))
    return findings


def _apache(esecutore, ctl):
    findings, note = [], []
    r, errore = esegui(esecutore, [ctl, "-v"], timeout=30)
    if not errore:
        m = re.search(r"Apache/(\S+)(?:\s+\(([^)]+)\))?", r.stdout or "")
        if m:
            findings.append(info_interno("webserver", f"Apache {m.group(1)}",
                                         f"Versione di Apache installata: {m.group(0)}.",
                                         elemento="apache", key="apache-versione"))
    cartelle = ["/etc/apache2", "/etc/httpd"]
    r, errore = esegui(esecutore, ["grep", "-rhiE",
                                   r"^\s*(ServerTokens|ServerSignature|SSLProtocol|Header|TraceEnable)\b",
                                   *cartelle], sudo=True, timeout=60)
    # grep: 0 = trovate, 1 = nessuna riga (configurazione di default), 2 = errore (es. una
    # delle due cartelle manca: le righe dell'altra sono comunque valide)
    if errore or (r.returncode == 2 and not r.stdout):
        note.append(f"configurazione di Apache non leggibile ({errore or prima_riga(r.stderr)})")
        return findings, note
    findings += _finding_apache(analizza_apache(r.stdout))
    return findings, note


def raccogli(esecutore):
    """Configurazione di nginx e/o Apache. Restituisce (findings, stato)."""
    findings, note, trovati = [], [], []
    if esecutore.which("nginx"):
        trovati.append("nginx")
        nuovi, n = _nginx(esecutore)
        findings += nuovi
        note += n
    ctl = next((c for c in ("apache2ctl", "apachectl", "httpd") if esecutore.which(c)), None)
    if ctl:
        trovati.append("Apache")
        nuovi, n = _apache(esecutore, ctl)
        findings += nuovi
        note += n
    if not trovati:
        return [], stato(NON_DISPONIBILE, "né nginx né Apache installati sulla macchina")
    letti = len(trovati) - len(note)
    if letti <= 0:
        return findings, stato(NON_DISPONIBILE, "; ".join(note))
    dettaglio = f"configurazione letta: {', '.join(trovati)}"
    return findings, stato(PARZIALE if note else ESEGUITO, "; ".join([dettaglio] + note))
