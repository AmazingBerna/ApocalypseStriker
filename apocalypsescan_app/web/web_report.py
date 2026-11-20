"""web_report.py - Pipeline del VAPT web, con l'analisi interna facoltativa.

Mette in fila: ricognizione (recon) -> valutazione (web_risk) -> [penetration testing attivo,
--pentest] -> [analisi interna della macchina, --inspect] -> modello unico -> report.
Il PT attivo e l'analisi interna hanno ciascuno un consenso dedicato.

Si lancia con  apocalypse attack <url>  oppure da solo
(python -m apocalypsescan_app.web.web_report <url>): le opzioni sono le stesse.
"""
import argparse
from datetime import datetime

from .. import banner
from ..config import WEB_AMBIENTI
from ..percorsi import percorso_output, scrivi
from ..progress import ProgressTracker, log
from ..renderers import csv_out, html_web, json_out
from ..renderers.markdown_web import render as render_web
from ..report_model import FINDING_FIELDS, _assign_ids, _normalize
from ..risk import sort_findings
from ..threat_intel import ThreatIntelError, load_threat_intel
from ..interno import comando as interno_cmd
from ..interno.analisi import analisi_interna, riepilogo_stato
from . import cve_nvd
from . import esito_pt
from . import interprete_web
from . import pentest as pentest_mod
from . import recon as recon_mod
from . import web_risk

MODE_VA = "VAPT web - Vulnerability Assessment (ricognizione passiva, sola lettura)"
MODE_VAPT = ("VAPT web - Vulnerability Assessment (passivo) + Penetration Testing (attivo: "
             "payload inviati al bersaglio)")
MODE_PIU_INTERNO = " + Analisi interna della macchina (accesso autorizzato, sola lettura)"

# Renderer del report web. markdown_web e html_web sono specifici del modello web; json_out
# (il modello in JSON) e csv_out (la lista dei finding) lavorano su qualunque modello e non
# vanno toccati. L'HTML riceve anche la spiegazione guidata, se richiesta (--interpreta).
RENDERERS_WEB = {
    "md": render_web,
    "html": html_web.render,
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
        else:
            log(f"[AVVISO] Formato '{nome}' non riconosciuto: saltato "
                f"(disponibili: {', '.join(RENDERERS_WEB)}).")
    return formati or list(DEFAULT_FORMATI_WEB)


def build_web_model(recon_result, findings, mode=MODE_VA, intel=None, host_interno=None,
                    pentest=None):
    """Modello del report: meta + ricognizione + finding normalizzati e con id.
    Tutti i finding (web passivi, PT attivo, analisi interna) hanno lo stesso schema
    FINDING_FIELDS e finiscono nella stessa tabella. host_interno: la macchina dell'analisi
    interna, usata come host dei finding con fonte "interno". pentest: il meta del
    penetration testing (None se non eseguito), che serve all'Esito PT di ogni finding."""
    host = recon_result.get("host")
    target = recon_result.get("target")
    http = recon_result.get("http", {})

    # l'esito si calcola sui finding grezzi: hanno ancora la key pt-<classe>-...
    esito_pt.assegna_esiti(findings, pentest)
    # un solo ordinamento per tutti (passivi, PT, interni): la tabella è ordinata dal rischio più alto
    findings = sort_findings(findings)
    norm = [_normalize(f, (host_interno or host) if f.get("fonte") == "interno" else host, target)
            for f in findings]
    _assign_ids(norm)
    norm = [{k: f[k] for k in FINDING_FIELDS} for f in norm]

    classi = recon_result.get("classi", {})
    model = {
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
    if pentest is not None:
        model["meta"]["pentest"] = pentest
    return model


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


def fasi_web(nvd=True, pentest=False, interno=False):
    """Fasi della barra di avanzamento, nell'ordine in cui vengono eseguite. Con pentest
    si aggiungono la scoperta (crawl) e il test attivo; con interno le voci dell'analisi
    interna; poi la scrittura del report."""
    fasi = ["web_recon"] + (["web_cve", "threat_intel"] if nvd else [])
    if pentest:
        fasi += ["web_crawl", "web_pentest"]
    if interno:
        fasi += interno_cmd.fasi_interne()
    return fasi + ["report"]


def _esegui_va(url, nvd=True, progress=None):
    """Ricognizione passiva + CVE + scoring. Restituisce (recon_result, findings_grezzi,
    intel): i finding NON sono ancora normalizzati, così si possono unire a quelli del
    penetration testing prima di costruire un unico modello."""
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
    return risultato, findings, intel


def vulnerability_assessment(url, nvd=True, progress=None):
    """Esegue il solo Vulnerability Assessment (passivo) e restituisce il modello del report.
    nvd=False non interroga NVD. progress: ProgressTracker creato con fasi_web(nvd)."""
    risultato, findings, intel = _esegui_va(url, nvd, progress)
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
                        help="Formati del report separati da virgola: md, html, json, csv "
                             "(default: md). Ognuno finisce in reports/<formato>/")
    parser.add_argument("--yes", action="store_true",
                        help="Salta la richiesta interattiva di conferma autorizzazione (e, con "
                             "--pentest, anche il secondo consenso)")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Non cercare le CVE su NVD: prodotto e versione delle tecnologie "
                             "rilevate non escono dalla macchina")
    parser.add_argument("--pentest", action="store_true",
                        help="Esegue anche il Penetration Testing ATTIVO (invia payload al "
                             "bersaglio): richiede un secondo consenso dedicato")
    parser.add_argument("--no-crawl", action="store_true",
                        help="Con --pentest: testa solo l'URL dato e i suoi form, senza esplorare "
                             "i link interni")
    parser.add_argument("--yes-pentest", action="store_true",
                        help="Con --pentest: salta il secondo consenso dell'attivo (automazione)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Non mostrare l'animazione del drago all'avvio")
    parser.add_argument("--interpreta", action="store_true",
                        help="Genera anche la spiegazione guidata dei risultati (regole fisse, "
                             "offline): reports/md/<nome>_interpretazione.md e lettura a terminale")
    interno_cmd.aggiungi_opzioni(parser, con_flag_inspect=True)
    args = parser.parse_args(argv)
    if args.yes and args.env is None:
        parser.error("con --yes l'ambiente va indicato con --env: il report non può esserne privo")
    try:
        url, _ = recon_mod.normalizza_url(args.url)    # si conferma l'URL che verrà davvero contattato
    except ValueError as e:
        parser.error(str(e))
    if interno_cmd.opzioni_interne_usate(args) and not args.inspect:
        parser.error("--host, --user, --key, --code e --semgrep-rules servono all'analisi interna: "
                     "aggiungi --inspect")
    conn = esecutore = None
    if args.inspect:
        try:
            conn = interno_cmd.parametri_connessione(args)
            esecutore = interno_cmd.crea_esecutore(conn)
        except interno_cmd.ErroreParametri as e:
            parser.error(str(e))

    # ApocalypseStriker è la forma risvegliata: il drago è sempre fucsia (RISVEGLIO).
    # L'animazione va prima di qualunque input() e della barra di avanzamento.
    if not args.no_banner:
        banner.intro(form=banner.RISVEGLIO)

    ambiente = args.env or chiedi_ambiente()
    autorizzazione = confirm_autorizzazione(url, ambiente, skip=args.yes)
    # Il penetration testing attivo ha un SECONDO consenso dedicato, chiesto prima della
    # barra di avanzamento (come l'autorizzazione): --yes o --yes-pentest lo saltano.
    # Il PT usa l'URL con la query CONSERVATA (recon.normalizza_url la toglie): i parametri
    # sono proprio ciò che va testato.
    url_pt = pentest_mod.normalizza_pt(args.url) if args.pentest else None
    if args.pentest:
        pentest_mod.confirm_pentest(url_pt, skip=args.yes or args.yes_pentest)
    # L'analisi interna ha la SUA autorizzazione (host, utente, data): accedere alla macchina
    # con credenziali è un'attività diversa dal leggere l'applicazione da fuori.
    autorizzazione_int = None
    if args.inspect:
        autorizzazione_int = interno_cmd.confirm_inspect(conn, esecutore, args.code, skip=args.yes)

    progress = ProgressTracker(fasi_web(nvd=not args.no_nvd, pentest=args.pentest,
                                        interno=args.inspect))
    progress.start()
    risultato, findings, intel = _esegui_va(url, nvd=not args.no_nvd, progress=progress)
    pentest_meta = None
    if args.pentest:
        pt_findings, pentest_meta = pentest_mod.penetration_test(
            url_pt, crawl_attivo=not args.no_crawl, progress=progress, log=log)
        findings = findings + pt_findings
    meta_int = None
    if args.inspect:
        int_findings, meta_int = analisi_interna(
            esecutore, codice=args.code, semgrep_rules=args.semgrep_rules, nvd=not args.no_nvd,
            intel=intel, progress=progress)
        findings = findings + int_findings
    mode = (MODE_VAPT if args.pentest else MODE_VA) + (MODE_PIU_INTERNO if args.inspect else "")
    model = build_web_model(risultato, findings, mode=mode, intel=intel,
                            host_interno=autorizzazione_int["host"] if autorizzazione_int else None,
                            pentest=pentest_meta)
    model["meta"]["autorizzazione"] = autorizzazione
    if meta_int is not None:
        model["meta"]["interno"] = meta_int
        model["meta"]["autorizzazione_interna"] = autorizzazione_int
        model["meta"]["interno"]["bersaglio"] = interno_cmd.descrizione_bersaglio(conn, esecutore)
    progress.begin("report", "Generazione report")
    nome = args.output or f"web_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    percorsi, lettura = scrivi_report(model, parse_formati_web(args.format), nome, args.interpreta)
    progress.end()
    progress.finish()

    if meta_int is not None:
        print("\nStato dell'analisi interna:")
        for riga in riepilogo_stato(meta_int):
            print(f"  - {riga}")
    stampa_esito(model, percorsi, lettura, nome)
    return 0


def scrivi_report(model, formati, nome, interpreta=False):
    """Scrive il modello in tutti i formati richiesti. Restituisce (percorsi, lettura):
    lettura è la spiegazione guidata (None senza interpreta)."""
    # la spiegazione guidata si calcola prima dei report: l'HTML la include
    lettura = interprete_web.interpreta_web(model) if interpreta else None
    percorsi = []
    for fmt in formati:
        testo = (RENDERERS_WEB[fmt](model, lettura) if fmt == "html"
                 else RENDERERS_WEB[fmt](model))
        # il CSV porta il BOM (utf-8-sig) come nel report host: così Excel lo apre bene
        percorsi.append(scrivi(percorso_output(nome, fmt), testo,
                               encoding="utf-8-sig" if fmt == "csv" else "utf-8"))
    return percorsi, lettura


def stampa_esito(model, percorsi, lettura, nome):
    """Riepilogo a terminale: conteggi, percorsi dei report e, se c'è, la lettura guidata."""
    scored = [f for f in model["findings"] if f["impact"] is not None]
    print(f"\n[OK] {len(scored)} finding valutati, "
          f"{len(model['findings']) - len(scored)} informativi.")
    pentest_meta = model["meta"].get("pentest")
    if pentest_meta is not None:
        attivi = len([f for f in model["findings"] if f["source"] == "pentest" and f["impact"]])
        print(f"[OK] Penetration testing attivo: {attivi} vulnerabilità confermate "
              f"({pentest_meta['punti_input']} punti di input, {pentest_meta['richieste']} richieste"
              + (", scansione troncata per budget" if pentest_meta.get("troncato") else "") + ").")
    if model["meta"].get("interno") is not None:
        interni = len([f for f in scored if f.get("fonte") == "interno"])
        print(f"[OK] Analisi interna: {interni} finding valutati.")
    for percorso in percorsi:
        print(f"[OK] Report scritto: {percorso}")

    if lettura is not None:
        # dal modello già in memoria: niente rilettura del JSON
        percorso_lettura = interprete_web.salva(lettura, nome)
        print(f"[OK] Interpretazione scritta: {percorso_lettura}")
        interprete_web.print_interpretazione(lettura, percorso_lettura)


if __name__ == "__main__":
    raise SystemExit(main())
