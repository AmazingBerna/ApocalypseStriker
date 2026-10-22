"""web_report.py - Pipeline del Vulnerability Assessment web (passivo).

Mette in fila: ricognizione (recon) -> valutazione (web_risk) -> modello -> report Markdown.
È il primo anello del VAPT, interamente in sola lettura. Il penetration testing attivo
(OWASP ZAP) sarà un modulo e una fase separati, con la loro conferma dedicata.

Si lancia con  apocalypse attack <url>  oppure da solo
(python -m apocalypsescan_app.web.web_report <url>): le opzioni sono le stesse.
"""
import argparse
from datetime import datetime

from .. import banner
from ..config import WEB_AMBIENTI
from ..percorsi import percorso_output, scrivi
from ..progress import ProgressTracker, log
from ..renderers import csv_out, json_out
from ..renderers.markdown_web import render as render_web
from ..report_model import FINDING_FIELDS, _assign_ids, _normalize
from ..threat_intel import ThreatIntelError, load_threat_intel
from . import cve_nvd
from . import recon as recon_mod
from . import web_risk

MODE_VA = "VAPT web - Vulnerability Assessment (ricognizione passiva, sola lettura)"

# Renderer del report web. markdown_web è specifico del modello web; json_out (il modello
# in JSON) e csv_out (la lista dei finding) lavorano su qualunque modello e non vanno toccati.
# L'HTML resta fuori: html_out.py è host-specifico (legge hosts/porte); il renderer HTML del
# web (html_web.py) arriverà a parte.
RENDERERS_WEB = {
    "md": render_web,
    "json": json_out.render,
    "csv": csv_out.render,
}
DEFAULT_FORMATI_WEB = ("md",)


def parse_formati_web(testo):
    """'md,json' -> ['md','json']; i formati non validi per il web vengono segnalati e saltati.
    Se non ne resta nessuno si ripiega sul Markdown."""
    formati = []
    for nome in (testo or "").split(","):
        nome = nome.strip().lower()
        if not nome or nome in formati:
            continue
        if nome in RENDERERS_WEB:
            formati.append(nome)
        elif nome == "html":
            log("[AVVISO] Il report HTML non è ancora disponibile per il web: 'html' saltato.")
        else:
            log(f"[AVVISO] Formato '{nome}' non riconosciuto: saltato "
                f"(disponibili: {', '.join(RENDERERS_WEB)}).")
    return formati or list(DEFAULT_FORMATI_WEB)


def build_web_model(recon_result, findings, mode=MODE_VA, intel=None):
    """Modello del report web: meta + ricognizione + finding normalizzati e con id.
    Riusa _normalize/_assign_ids/FINDING_FIELDS del modello host, così i finding web
    hanno esattamente lo stesso schema (e gli stessi id stabili)."""
    host = recon_result.get("host")
    target = recon_result.get("target")
    http = recon_result.get("http", {})

    norm = [_normalize(f, host, target) for f in findings]
    _assign_ids(norm)
    norm = [{k: f[k] for k in FINDING_FIELDS} for f in norm]

    classi = recon_result.get("classi", {})
    return {
        "meta": {
            "target": target,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "mode": mode,
            "host": host,
            "http_status": http.get("status"),
            "final_url": http.get("final_url"),
            "redirected": http.get("redirected", False),
            "upgraded_https": http.get("upgraded_https", False),
            "http_error": http.get("error"),
            "http_tls_unverified": http.get("verifica_tls_fallita"),
            "tool": "ApocalypseStriker recon (sola lettura, libreria standard)",
            "threat_intel": intel.meta() if intel is not None else None,
        },
        "tecnologie": classi.get("tecnologie", {}),
        "tecnologie_rilevate": recon_result.get("tecnologie_rilevate", []),
        "tls": recon_result.get("tls"),
        "findings": norm,
    }


def _carica_intel():
    """Dati KEV/EPSS per la probabilità delle CVE. Se non disponibili si prosegue con i
    valori di ripiego: per il VA web le CVE sono una parte, non tutta la scansione."""
    try:
        return load_threat_intel()
    except ThreatIntelError as e:
        log(f"[!] KEV/EPSS non disponibili ({e}): probabilità delle CVE da CVSS o valori fissi.")
        return None


class _SenzaBarra:
    """Sostituto di ProgressTracker quando la pipeline è chiamata da codice: nessun output."""
    def begin(self, phase, label):
        pass

    def end(self, ok=True):
        pass


def fasi_web(nvd=True):
    """Fasi della barra di avanzamento, nell'ordine in cui vulnerability_assessment le esegue."""
    return ["web_recon"] + (["web_cve", "threat_intel"] if nvd else []) + ["report"]


def vulnerability_assessment(url, nvd=True, progress=None):
    """Esegue recon + ricerca CVE + scoring e restituisce il modello del report web.
    nvd=False non interroga NVD (nessun dato sulle tecnologie esce dalla macchina).
    progress: ProgressTracker creato con fasi_web(nvd); None = nessuna barra."""
    fasi = progress or _SenzaBarra()

    fasi.begin("web_recon", "Ricognizione passiva (HTTP, TLS)")
    risultato = recon_mod.recon(url)
    fasi.end(ok="error" not in risultato["http"])

    tecnologie = risultato.get("tecnologie_rilevate", [])
    intel = None
    if nvd:
        fasi.begin("web_cve", "CVE note delle tecnologie (NVD)")
        cve_nvd.arricchisci(tecnologie)
        fasi.end(ok=not any("cve_errore" in t for t in tecnologie))
        fasi.begin("threat_intel", "Dati sulle minacce (KEV, EPSS)")
        # KEV ed EPSS servono solo se ci sono CVE da pesare
        if any(t.get("cve") for t in tecnologie):
            intel = _carica_intel()
            fasi.end(ok=intel is not None)
        else:
            fasi.end()
    else:
        cve_nvd.arricchisci(tecnologie, attivo=False)

    findings = web_risk.valuta_recon(risultato, intel)
    return build_web_model(risultato, findings, intel=intel)


def _leggi(domanda):
    """input() che tratta fine dell'input (Ctrl+D/Ctrl+Z) e Ctrl+C come un rifiuto: si esce
    senza scansione e senza traceback."""
    try:
        return input(domanda)
    except (EOFError, KeyboardInterrupt):
        print("\nConferma non ricevuta. Uscita.")
        raise SystemExit(0)


def chiedi_ambiente():
    """Chiede l'ambiente dell'applicazione finché la risposta non è uno di WEB_AMBIENTI
    (numero o nome)."""
    elenco = "  ".join(f"{n}) {a}" for n, a in enumerate(WEB_AMBIENTI, 1))
    while True:
        risposta = _leggi(f"Ambiente dell'applicazione? {elenco}: ").strip().lower()
        if risposta.isdigit() and 1 <= int(risposta) <= len(WEB_AMBIENTI):
            return WEB_AMBIENTI[int(risposta) - 1]
        if risposta in WEB_AMBIENTI:
            return risposta
        print(f"Risposta non valida: scegli tra {', '.join(WEB_AMBIENTI)}.")


def confirm_autorizzazione(url, ambiente, skip=False):
    """Prompt di autorizzazione all'avvio con URL, ambiente e data, come richiesto dai
    vincoli di sicurezza. Restituisce i dati dell'autorizzazione da scrivere nel report.
    Qui l'attività è passiva; l'active scan ZAP avrà in più un SECONDO prompt, dedicato."""
    momento = datetime.now()
    print("=" * 70)
    print("AUTORIZZAZIONE")
    print("ApocalypseStriker sta per eseguire una RICOGNIZIONE PASSIVA (sola lettura):")
    print("legge header, cookie e TLS come un browser. Nessun payload, nessun attacco.")
    print(f"  URL:      {url}")
    print(f"  Ambiente: {ambiente}")
    print(f"  Data:     {momento.strftime('%Y-%m-%d %H:%M')}")
    print("L'applicazione dev'essere di tua proprietà o con autorizzazione scritta a testarla.")
    print("Analizzare un sito altrui senza permesso è un reato.")
    print("=" * 70)
    if not skip:
        risposta = _leggi("Confermi di essere autorizzato su questo URL? [scrivi 'si' per continuare]: ")
        if risposta.strip().lower() not in ("si", "sì", "yes", "y"):
            print("Conferma non ricevuta. Uscita.")
            raise SystemExit(0)
    return {"ambiente": ambiente, "confermata_il": momento.isoformat(timespec="seconds"),
            "modo": "non interattiva, --yes" if skip else "interattiva"}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="apocalypse attack",
        description="Vulnerability Assessment passivo di un'applicazione web: header di "
                    "sicurezza, cookie, TLS e tecnologie esposte. Sola lettura.")
    parser.add_argument("url", help="URL dell'applicazione (es. https://esempio.it)")
    parser.add_argument("--output", default=None,
                        help="Nome del report (default: web_<timestamp>); senza cartella finisce "
                             "in reports/md/")
    parser.add_argument("--env", choices=WEB_AMBIENTI, default=None,
                        help="Ambiente dell'applicazione (se manca viene chiesto; obbligatorio con --yes)")
    parser.add_argument("--format", default="md",
                        help="Formati del report separati da virgola: md, json, csv (default: md). "
                             "L'HTML per il web arriverà in una prossima versione.")
    parser.add_argument("--yes", action="store_true",
                        help="Salta la richiesta interattiva di conferma autorizzazione")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Non cercare le CVE su NVD: prodotto e versione delle tecnologie "
                             "rilevate non escono dalla macchina")
    parser.add_argument("--no-banner", action="store_true",
                        help="Non mostrare l'animazione del drago all'avvio")
    args = parser.parse_args(argv)
    if args.yes and args.env is None:
        parser.error("con --yes l'ambiente va indicato con --env: il report non può esserne privo")
    try:
        url, _ = recon_mod.normalizza_url(args.url)    # si conferma l'URL che verrà davvero contattato
    except ValueError as e:
        parser.error(str(e))

    # ApocalypseStriker è la forma risvegliata: il drago è sempre fucsia (RISVEGLIO).
    # L'animazione va prima di qualunque input() e della barra di avanzamento.
    if not args.no_banner:
        banner.intro(form=banner.RISVEGLIO)

    ambiente = args.env or chiedi_ambiente()
    autorizzazione = confirm_autorizzazione(url, ambiente, skip=args.yes)

    progress = ProgressTracker(fasi_web(nvd=not args.no_nvd))
    progress.start()
    model = vulnerability_assessment(url, nvd=not args.no_nvd, progress=progress)
    model["meta"]["autorizzazione"] = autorizzazione
    formati = parse_formati_web(args.format)
    progress.begin("report", "Generazione report")
    nome = args.output or f"web_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    percorsi = []
    for fmt in formati:
        testo = RENDERERS_WEB[fmt](model)
        # il CSV porta il BOM (utf-8-sig) come nel report host: così Excel lo apre bene
        percorsi.append(scrivi(percorso_output(nome, fmt), testo,
                               encoding="utf-8-sig" if fmt == "csv" else "utf-8"))
    progress.end()
    progress.finish()

    scored = [f for f in model["findings"] if f["impact"] is not None]
    print(f"\n[OK] {len(scored)} finding valutati, "
          f"{len(model['findings']) - len(scored)} informativi.")
    for percorso in percorsi:
        print(f"[OK] Report scritto: {percorso}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
