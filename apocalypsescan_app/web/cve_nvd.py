"""cve_nvd.py - CVE note per le tecnologie con versione, dal National Vulnerability Database.

Interroga NVD, non il bersaglio: a NVD arriva solo il CPE "produttore:prodotto:versione"
(es. f5:nginx:1.10.3), mai l'URL o il nome dell'host analizzato. È comunque un'informazione
che esce dalla macchina, a differenza di KEV ed EPSS che threat_intel.py scarica interi:
per questo le risposte restano in cache (NVD_CACHE_HOURS) e la ricerca si può disattivare
(web_report --no-nvd).

Comportamenti di NVD osservati il 22/10/2026 su cui si basa il modulo:
- cpeName funziona; virtualMatchString ha risposto 503;
- un CPE inesistente (prodotto o versione) NON dà errore: risponde 0 CVE. Zero CVE quindi
  non prova l'assenza di vulnerabilità, e il report lo deve dire;
- le CVE più vecchie hanno solo la metrica CVSS v2 (cvssMetricV2).
"""
import hashlib
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..config import (
    NVD_API_URL, NVD_API_KEY_ENV, NVD_PAUSE, NVD_TIMEOUT, NVD_CACHE_HOURS, WEB_TECH_CPE,
)
from ..threat_intel import _writable_cache

UA = "ApocalypseStriker-cve/0.1"
TENTATIVI = 3            # NVD risponde spesso 503/429 sotto carico: si ritenta dopo una pausa
PAUSA_ERRORE = 10

_ultima_richiesta = 0.0  # per rispettare il limite di richieste di NVD tra una chiamata e l'altra


class NvdError(Exception):
    """La ricerca su NVD non è riuscita (rete, limiti, risposta non valida)."""


def cpe_per(prodotto, versione):
    """CPE 2.3 di NVD per un prodotto con versione, o None se il prodotto non è mappato."""
    voce = WEB_TECH_CPE.get(prodotto.lower())
    if voce is None or not versione:
        return None
    produttore, nome = voce
    return f"cpe:2.3:a:{produttore}:{nome}:{versione}:*:*:*:*:*:*:*"


def _metrica(cve):
    """(gravità, punteggio, vettore) dalla metrica CVSS più recente disponibile."""
    metriche = cve.get("metrics", {})
    for chiave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metriche.get(chiave):
            m = metriche[chiave][0]
            dati = m.get("cvssData", {})
            # nella v2 la gravità sta fuori da cvssData
            gravita = dati.get("baseSeverity") or m.get("baseSeverity")
            return gravita, dati.get("baseScore"), dati.get("vectorString")
    return None, None, None


def _richiesta(cpe):
    """Una chiamata all'API NVD per il CPE, con pausa tra le richieste e nuovi tentativi."""
    global _ultima_richiesta
    chiave = os.environ.get(NVD_API_KEY_ENV)
    headers = {"User-Agent": UA}
    if chiave:
        headers["apiKey"] = chiave
    pausa = NVD_PAUSE[1] if chiave else NVD_PAUSE[0]
    url = f"{NVD_API_URL}?{urlencode({'cpeName': cpe, 'resultsPerPage': 2000})}"

    for tentativo in range(TENTATIVI):
        attesa = _ultima_richiesta + pausa - time.monotonic()
        if attesa > 0:
            time.sleep(attesa)
        _ultima_richiesta = time.monotonic()
        try:
            with urlopen(Request(url, headers=headers), timeout=NVD_TIMEOUT) as risposta:
                return json.load(risposta)
        except HTTPError as e:
            if e.code not in (403, 429, 503) or tentativo == TENTATIVI - 1:
                raise NvdError(f"NVD ha risposto HTTP {e.code} {e.reason}") from e
        except (URLError, OSError, ValueError) as e:
            if tentativo == TENTATIVI - 1:
                raise NvdError(f"NVD non raggiungibile: {getattr(e, 'reason', e)}") from e
        time.sleep(PAUSA_ERRORE)


def cerca_cve(cpe):
    """CVE di NVD per il CPE: lista di {id, gravita, punteggio, vettore}, escluse le
    respinte. Restituisce (lista, 'cache' | 'nvd'); solleva NvdError se non riesce."""
    cartella = _writable_cache() / "nvd"
    cartella.mkdir(exist_ok=True)
    file = cartella / (hashlib.sha1(cpe.encode()).hexdigest()[:16] + ".json")
    if file.exists() and time.time() - file.stat().st_mtime < NVD_CACHE_HOURS * 3600:
        return json.loads(file.read_text(encoding="utf-8"))["cve"], "cache"

    dati = _richiesta(cpe)
    elenco = []
    for voce in dati.get("vulnerabilities", []):
        cve = voce.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        gravita, punteggio, vettore = _metrica(cve)
        elenco.append({"id": cve["id"], "gravita": gravita, "punteggio": punteggio, "vettore": vettore})
    file.write_text(json.dumps({"cpe": cpe, "cve": elenco}), encoding="utf-8")
    return elenco, "nvd"


def arricchisci(tecnologie, attivo=True):
    """Segna su ogni tecnologia se il prodotto è 'mappato' su NVD; a quelle mappate e con
    versione aggiunge 'cpe' e 'cve' (lista), oppure 'cve_errore'. Con attivo=False non
    interroga NVD e lo segna in 'cve_errore'."""
    for t in tecnologie:
        t["mappato"] = t["prodotto"].lower() in WEB_TECH_CPE
        cpe = cpe_per(t["prodotto"], t["versione"])
        if cpe is None:
            continue
        t["cpe"] = cpe
        if not attivo:
            t["cve_errore"] = "ricerca CVE su NVD disattivata (--no-nvd)"
            continue
        try:
            t["cve"], t["cve_fonte"] = cerca_cve(cpe)
        except NvdError as e:
            t["cve_errore"] = str(e)
    return tecnologie


if __name__ == "__main__":
    import sys
    for argomento in sys.argv[1:] or ["nginx/1.10.3"]:
        prodotto, _, versione = argomento.partition("/")
        cpe = cpe_per(prodotto, versione)
        if cpe is None:
            print(f"{argomento}: prodotto non mappato o senza versione")
            continue
        elenco, fonte = cerca_cve(cpe)
        print(f"{argomento}: {len(elenco)} CVE ({fonte})  {cpe}")
        for c in sorted(elenco, key=lambda c: c["punteggio"] or 0, reverse=True)[:5]:
            print(f"   {c['id']:<16} {str(c['gravita']):<9} {c['punteggio']}  {c['vettore']}")
