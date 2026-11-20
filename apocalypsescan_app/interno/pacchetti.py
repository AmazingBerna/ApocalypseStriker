"""pacchetti.py - Versioni dei pacchetti chiave e CVE note (NVD), dall'interno.

Legge con dpkg-query (o rpm) la versione dei pacchetti dei servizi in ascolto e di alcuni
pacchetti chiave (web server, database, OpenSSL, OpenSSH, PHP). Per i prodotti che il VA web
sa già mappare su NVD (config.WEB_TECH_CPE: nginx, Apache, OpenSSL, PHP) cerca le CVE note
con lo stesso codice del VA web (cve_nvd + web_risk._valuta_cve), così le CVE interne ed
esterne hanno la stessa valutazione.

Le versioni dei pacchetti di distribuzione ricevono patch senza cambiare numero (backport):
la probabilità delle CVE resta quindi bassa (lo stesso tetto del banner "(Ubuntu)").
A NVD arriva solo il CPE prodotto:versione, mai il nome o l'indirizzo della macchina.
"""
import re

from ..config import INT_PACCHETTI_CHIAVE, INT_PACCHETTI_PRODOTTO
from ..web import cve_nvd, web_risk
from .comune import ESEGUITO, NON_DISPONIBILE, PARZIALE, esegui, info_interno, stato


def versione_upstream(versione):
    """'1:1.18.0-6ubuntu14.4' -> '1.18.0'; None se non ha la forma x.y.z (es. metapacchetti)."""
    if not versione:
        return None
    v = versione.split(":", 1)[-1]          # epoca
    v = v.rsplit("-", 1)[0]                 # revisione della distribuzione
    m = re.match(r"[0-9]+(?:\.[0-9]+){2,}[a-z]?", v)
    return m.group(0) if m else None


def parse_versioni(testo):
    """Righe "pacchetto<TAB>versione" -> {pacchetto: versione} (scarta i non installati)."""
    versioni = {}
    for riga in (testo or "").splitlines():
        if "\t" not in riga:
            continue
        nome, versione = riga.split("\t", 1)
        if nome.strip() and versione.strip():
            versioni[nome.strip()] = versione.strip()
    return versioni


def _leggi_versioni(esecutore, gestore, nomi):
    if gestore == "dpkg":
        args = ["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\n", *nomi]
    else:
        args = ["rpm", "-q", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n", *nomi]
    r, errore = esegui(esecutore, args, timeout=60)
    if errore:
        return None, errore
    # escono con 1 se qualche pacchetto non è installato: le righe trovate restano valide
    return parse_versioni(r.stdout), None


def raccogli(esecutore, servizi=None, nvd=False, intel=None, arricchisci=None):
    """Pacchetti chiave e CVE note. arricchisci: per i test (default cve_nvd.arricchisci).
    Restituisce (findings, stato)."""
    gestore = (servizi or {}).get("manager")
    if gestore is None:
        gestore = "dpkg" if esecutore.which("dpkg-query") else ("rpm" if esecutore.which("rpm") else None)
    if gestore is None:
        return [], stato(NON_DISPONIBILE, "né dpkg né rpm presenti: versioni dei pacchetti non lette")

    nomi = list(INT_PACCHETTI_CHIAVE)
    for s in (servizi or {}).get("services", []):
        if s.get("package") and s["package"] not in nomi:
            nomi.append(s["package"])
    versioni, errore = _leggi_versioni(esecutore, gestore, nomi)
    if errore:
        return [], stato(NON_DISPONIBILE, f"lettura delle versioni non riuscita: {errore}")
    if not versioni:
        return [], stato(ESEGUITO, "nessuno dei pacchetti chiave è installato")

    findings = [info_interno(
        "pacchetti", f"Pacchetti chiave installati: {len(versioni)}",
        "; ".join(f"{n} {v}" for n, v in sorted(versioni.items())),
        elemento=f"pacchetti ({gestore})", key="pacchetti-chiave")]

    tecnologie, viste = [], set()
    for nome, versione in sorted(versioni.items()):
        prodotto = INT_PACCHETTI_PRODOTTO.get(nome)
        upstream = versione_upstream(versione)
        if not prodotto or not upstream or (prodotto, upstream) in viste:
            continue
        viste.add((prodotto, upstream))
        tecnologie.append({"prodotto": prodotto, "versione": upstream,
                           "evidenza": f"pacchetto {nome} {versione}", "distro": gestore})
    (arricchisci or cve_nvd.arricchisci)(tecnologie, attivo=nvd)
    for f in web_risk._valuta_cve(tecnologie, None, intel):
        f["source"] = "pacchetti"
        f["fonte"] = "interno"
        f["elemento"] = f.get("evidence", "").split(" → ")[0] or "pacchetti"
        f.setdefault("key", f"pkg-{f['item']}")
        findings.append(f)

    nota = "" if nvd else "; CVE non cercate (NVD disattivato)"
    esito = ESEGUITO if nvd or not tecnologie else PARZIALE
    return findings, stato(esito, f"{len(versioni)} pacchetti chiave letti con {gestore}{nota}")
