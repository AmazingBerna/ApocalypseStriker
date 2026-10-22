"""zap_scan.py - Wrapper di OWASP ZAP (daemon + API), via HTTP standard.

ZAP gira come daemon (nel container Docker, vedi README) e viene pilotato dalla sua API
REST. Questo modulo non implementa exploit: avvia gli strumenti standard di ZAP e ne
traduce gli alert nel nostro modello di finding (categoria OWASP + impatto x probabilità).

Due livelli di invasività, nettamente separati:
  - PASSIVO  (spider + passive scan): ZAP naviga e osserva, non attacca il bersaglio.
  - ATTIVO   (active scan): invia richieste di prova. È l'unica parte che sollecita il
             bersaglio, protetta da una conferma dedicata (confirm_active_scan).

Comunicazione: solo libreria standard (urllib), come recon.py. L'API di ZAP risponde in JSON.
"""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from ..config import (
    OWASP, ZAP_API_DEFAULT, ZAP_CONFIDENCE_PROBABILITY, ZAP_RISK_IMPACT, ZAP_SKIP_CONFIDENCE,
)
from ..risk import info_finding, make_finding, sort_findings

TIMEOUT = 30          # secondi per ogni chiamata all'API
POLL_OGNI = 2         # secondi fra un controllo di avanzamento e il successivo


class ZapError(RuntimeError):
    """Problema nel parlare con il daemon ZAP (non raggiungibile, errore dell'API)."""


def _api(base, path, **params):
    """Chiama un endpoint JSON dell'API di ZAP e restituisce il dizionario di risposta.
    Gli endpoint /action/ cambiano stato (avviano scansioni); i /view/ leggono soltanto."""
    url = base.rstrip("/") + path
    if params:
        url += "?" + urlencode(params)
    try:
        with urlopen(url, timeout=TIMEOUT) as r:
            dati = json.load(r)
    except HTTPError as e:
        raise ZapError(f"ZAP ha risposto {e.code} a {path}: {e.read()[:200]!r}") from e
    except (URLError, OSError, json.JSONDecodeError) as e:
        raise ZapError(f"Daemon ZAP non raggiungibile su {base} ({type(e).__name__}: {e}). "
                       "È avviato? Vedi README (docker run ... zap.sh -daemon).") from e
    if isinstance(dati, dict) and dati.get("code") and dati.get("message"):
        raise ZapError(f"Errore API ZAP su {path}: {dati['code']} - {dati['message']}")
    return dati


def versione(base=ZAP_API_DEFAULT):
    """Versione di ZAP: serve a verificare che il daemon risponda prima di iniziare."""
    return _api(base, "/JSON/core/view/version/").get("version")


# --------------------------------------------------------------------------
# Fase passiva: spider + passive scan (osservano soltanto)
# --------------------------------------------------------------------------

def _attendi(base, path, chiave, etichetta, target_valore="100", log=print, max_errori=5):
    """Interroga un /view/ finché il valore raggiunge target_valore (o scende a 0).
    Durante l'active scan ZAP è sotto carico e una singola chiamata può andare in timeout:
    gli errori transitori vengono ritentati (fino a max_errori di fila) senza interrompere
    l'attesa; solo un'indisponibilità persistente solleva l'errore."""
    errori = 0
    while True:
        try:
            valore = _api(base, path).get(chiave, "0")
            errori = 0
        except ZapError:
            errori += 1
            if errori > max_errori:
                raise
            if log:
                log(f"    {etichetta}: API occupata ({errori}/{max_errori}), riprovo...")
            time.sleep(POLL_OGNI)
            continue
        if log:
            log(f"    {etichetta}: {valore}")
        if valore == target_valore:
            return
        time.sleep(POLL_OGNI)


def spider(base, target, max_children=0, log=print):
    """Avvia lo spider di ZAP sul bersaglio e aspetta che finisca (sola navigazione)."""
    scan_id = _api(base, "/JSON/spider/action/scan/", url=target,
                   maxChildren=max_children).get("scan")
    _attendi(base, f"/JSON/spider/view/status/?scanId={scan_id}", "status",
             "spider", log=log)
    return scan_id


def attendi_passive(base, log=print):
    """Aspetta che la coda del passive scan si svuoti (ZAP ha analizzato tutte le risposte)."""
    _attendi(base, "/JSON/pscan/view/recordsToScan/", "recordsToScan",
             "passive scan (in coda)", target_valore="0", log=log)


def scansione_passiva(base, target, max_children=0, log=print):
    """Spider + passive scan completi. Non attacca: naviga e osserva. Restituisce gli alert."""
    if log:
        log(f"[*] ZAP {versione(base)} - scansione PASSIVA di {target}")
        log("    spider (navigazione)...")
    spider(base, target, max_children=max_children, log=log)
    if log:
        log("    attendo il passive scan...")
    attendi_passive(base, log=log)
    return alerts(base, target)


# --------------------------------------------------------------------------
# Fase attiva: active scan (sollecita il bersaglio) - sotto conferma dedicata
# --------------------------------------------------------------------------

def confirm_active_scan(target, skip=False):
    """SECONDO prompt, dedicato e separato dall'autorizzazione iniziale. L'active scan invia
    richieste di prova al bersaglio: non deve mai partire per sbaglio."""
    print("=" * 70)
    print("CONFERMA ACTIVE SCAN (operazione ad alto impatto)")
    print("L'active scan di ZAP INVIA richieste di prova al bersaglio: è intrusivo e può")
    print("generare errori, dati o carico sul server. Lo spider e il passive scan, invece,")
    print("hanno solo osservato.")
    print(f"  Bersaglio: {target}")
    print("Esegui l'active scan SOLO su sistemi tuoi o con autorizzazione scritta e su un")
    print("ambiente che può sostenerne l'impatto.")
    print("=" * 70)
    if skip:
        return
    risposta = input("Avviare l'ACTIVE SCAN su questo bersaglio? [scrivi 'attiva' per confermare]: ")
    if risposta.strip().lower() != "attiva":
        print("Conferma non ricevuta: active scan NON avviato.")
        raise SystemExit(0)


def active_scan(base, target, skip_confirm=False, log=print):
    """Active scan di ZAP, preceduto dalla conferma dedicata. Restituisce gli alert aggiornati."""
    confirm_active_scan(target, skip=skip_confirm)
    if log:
        log(f"[!] ZAP - ACTIVE SCAN di {target} (intrusivo)")
    scan_id = _api(base, "/JSON/ascan/action/scan/", url=target,
                   recurse="true", inScopeOnly="false").get("scan")
    _attendi(base, f"/JSON/ascan/view/status/?scanId={scan_id}", "status",
             "active scan", log=log)
    attendi_passive(base, log=log)   # l'active scan genera nuove risposte da far passare al passivo
    return alerts(base, target)


# --------------------------------------------------------------------------
# Alert -> finding del nostro modello
# --------------------------------------------------------------------------

def alerts(base, target=None):
    """Alert grezzi di ZAP, eventualmente filtrati per baseurl del bersaglio."""
    params = {"baseurl": target} if target else {}
    return _api(base, "/JSON/core/view/alerts/", **params).get("alerts", [])


def _owasp_da_tags(tags):
    """Estrae la categoria OWASP 2021 dai tag dell'alert (es. 'OWASP_2021_A05' -> etichetta)."""
    for chiave in (tags or {}):
        if chiave.startswith("OWASP_2021_A"):
            return OWASP.get(chiave.rsplit("_", 1)[-1])
    return None


def _riferimenti(alert):
    """Lista di riferimenti del finding: URL della voce 'reference' + CWE, se presente."""
    refs = [r for r in (alert.get("reference") or "").split() if r.startswith("http")]
    cwe = alert.get("cweid")
    if cwe and cwe not in ("-1", "0", ""):
        refs.append(f"CWE-{cwe}")
    return refs


def alert_a_finding(alert):
    """Converte un alert ZAP in un finding del modello; None se va scartato (falso positivo)."""
    confidence = alert.get("confidence")
    if confidence in ZAP_SKIP_CONFIDENCE:
        return None

    item = alert.get("name") or alert.get("alert") or "Alert ZAP"
    url = alert.get("url")
    reason = (alert.get("description") or item).strip()
    evidenza = (alert.get("evidence") or alert.get("param") or alert.get("attack") or "").strip()
    owasp = _owasp_da_tags(alert.get("tags"))
    extra = dict(owasp=owasp, url=url, evidence=evidenza, references=_riferimenti(alert))

    risk = alert.get("risk")
    if risk not in ZAP_RISK_IMPACT:          # "Informational": non valutato
        return info_finding("zap", item, reason, **extra)
    impatto = ZAP_RISK_IMPACT[risk]
    probabilita = ZAP_CONFIDENCE_PROBABILITY.get(confidence, 2)
    return make_finding("zap", item, impatto, probabilita, reason, **extra)


def valuta_alerts(lista_alerts):
    """Finding ordinati dagli alert di ZAP, AGGREGATI per tipo (pluginId + nome + parametro).
    ZAP emette un alert per ogni URL/istanza: lo stesso header mancante compare su ogni
    pagina. Nel report serve un solo finding per tipo, con quanti endpoint sono interessati
    e un esempio. Il parametro entra nella chiave perché in active scan la stessa regola su
    parametri diversi (es. SQLi su 'id' e su 'cat') sono finding distinti e reali."""
    gruppi = {}
    for a in lista_alerts:
        chiave = (a.get("pluginId"), a.get("name"), a.get("param") or "")
        gruppi.setdefault(chiave, []).append(a)

    findings = []
    for istanze in gruppi.values():
        f = alert_a_finding(istanze[0])
        if f is None:                       # tipo scartato (falso positivo): salta l'intero gruppo
            continue
        urls = sorted({a.get("url") for a in istanze if a.get("url")})
        f["references"] = sorted({r for a in istanze for r in _riferimenti(a)})
        base = (f.get("evidence") or "").strip()
        if len(istanze) > 1:
            esempio = f"{len(istanze)} endpoint interessati; es. {urls[0]}" if urls else f"{len(istanze)} istanze"
            f["evidence"] = f"{esempio} — {base}" if base else esempio
        elif not base:
            f["evidence"] = urls[0] if urls else None
        f["url"] = urls[0] if urls else f.get("url")
        findings.append(f)
    return sort_findings(findings)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collaudo del wrapper ZAP: scansione passiva "
                                                 "(spider + passive) e mappatura degli alert.")
    parser.add_argument("target", help="URL del bersaglio (già autorizzato)")
    parser.add_argument("--zap", default=ZAP_API_DEFAULT, help=f"API del daemon ZAP (default {ZAP_API_DEFAULT})")
    parser.add_argument("--active", action="store_true", help="Esegue anche l'active scan (conferma dedicata)")
    parser.add_argument("--yes-active", action="store_true", help="Salta la conferma dell'active scan (automazione)")
    parser.add_argument("--only-alerts", action="store_true",
                        help="Non scansiona: mappa gli alert già presenti nel daemon (per collaudo)")
    args = parser.parse_args()

    if args.only_alerts:
        grezzi = alerts(args.zap, args.target)
    else:
        grezzi = scansione_passiva(args.zap, args.target)
        if args.active:
            grezzi = active_scan(args.zap, args.target, skip_confirm=args.yes_active)

    findings = valuta_alerts(grezzi)
    print(f"\nBersaglio: {args.target}  —  {len(findings)} finding da {len(grezzi)} alert\n")
    for f in findings:
        punteggio = f"{f['score']:>2}" if f["score"] else " ·"
        print(f"  [{punteggio}] {f['level']:<12} {(f.get('owasp') or ''):<40} {f['item']}")
