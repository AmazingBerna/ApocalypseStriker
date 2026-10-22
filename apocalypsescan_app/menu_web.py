#!/usr/bin/env python3
"""
menu_web.py - Menù interattivo di ApocalypseStriker (comando: apocalypse attack)
======================================================================

La terza versione della serie Apocalypse: il drago, già risvegliato e fucsia, punta
le applicazioni web. Il menù ha lo stesso stile delle versioni precedenti (banner in
cima, larghezza 78, palette fucsia), con voci numerate adattate al VAPT web.

Lo stile (banner, cornici, domande) vive in menu_stile.py; qui ci sono le voci, le
sezioni della guida e la scansione guidata. Collega soltanto l'interfaccia: la
scansione vera è quella già esistente (apocalypsescan_app.web.web_report), richiamata
come sottoprocesso così che l'autorizzazione venga sempre chiesta.

Uso:
    apocalypse attack
oppure:
    python -m apocalypsescan_app.menu_web
"""

import shlex
import subprocess
import sys
from typing import NamedTuple

from apocalypsescan_app import __version__
from apocalypsescan_app import menu_stile as st
from apocalypsescan_app.config import WEB_AMBIENTI
from apocalypsescan_app.web.recon import normalizza_url

# Scorciatoie ai primitivi di stile (sempre fucsia): stesso aspetto delle versioni precedenti.
c = st.c
riga = st.riga
titolo_sezione = st.titolo_sezione
colora_testo = st.colora_testo
chiedi = st.chiedi
chiedi_si_no = st.chiedi_si_no
chiedi_scelta = st.chiedi_scelta
mostra_opzioni = st.mostra_opzioni
pulisci_schermo = st.pulisci_schermo
pausa = st.pausa
avviso = st.avviso
errore_input = st.errore_input
valida_url = st.valida_url
Passi = st.Passi
GRIGIO, GRASSETTO, ARANCIO, AVVISO = st.GRIGIO, st.GRASSETTO, st.ARANCIO, st.AVVISO
TITOLO, AZIONE, ACCENTO = st.TITOLO, st.AZIONE, st.ACCENTO

PRODOTTO = "VAPT di applicazioni web   Vulnerability Assessment + Penetration Testing"
SOTTOTITOLO = "S T R I K E R"


# --------------------------------------------------------------------------
# Testi della guida (stesso markup di menu_stile.colora_testo: "# " titolo,
# "! " avviso, "$ " comando, "--flag  descrizione", "[n]  voce  descrizione")
# --------------------------------------------------------------------------

COME_FUNZIONA = """\
# Che cos'è un VAPT

VAPT = Vulnerability Assessment + Penetration Testing: due fasi, due livelli di
invasività, lo stesso obiettivo di misurare il rischio di un'applicazione web.

  [1]  Vulnerability Assessment (passivo)  osserva e non tocca il bersaglio
       Legge header di sicurezza, cookie, TLS e tecnologie come farebbe un
       browser, e cerca le CVE note delle versioni rilevate. Sola lettura.

  [2]  Penetration Testing (attivo)  sollecita il bersaglio
       Invia richieste di prova per confermare le vulnerabilità. È intrusivo:
       va fatto solo su sistemi propri o con autorizzazione scritta, e qui è
       protetto da un secondo consenso dedicato.

# Il punteggio: Rischio = Impatto x Probabilità

Ogni finding vale Impatto x Probabilità. L'impatto è quanto fa male se accade;
la probabilità tiene conto di quanto è esposto e, per le CVE, dei dati CISA KEV
(sfruttata in concreto?) ed EPSS (quanto è probabile che venga sfruttata).

# Il report

Alla fine ottieni un report con i finding ordinati per rischio, l'autorizzazione
registrata e le tecnologie riconosciute. Vedi le voci 5 ed 6.
"""

PRIMA_DI_INIZIARE = """\
# Prima di iniziare: l'autorizzazione

! Analizza solo applicazioni di tua proprietà o per cui hai un'autorizzazione
! scritta a testarle. Analizzare un sito altrui senza permesso è un reato.

All'avvio di ogni scansione ApocalypseStriker mostra un prompt di AUTORIZZAZIONE
con URL, ambiente e data, e chiede conferma prima di procedere.

# Cosa scegliere come bersaglio

Un'applicazione web raggiungibile via http/https. Senza schema viene usato
https:// (es. esempio.it diventa https://esempio.it/).

# Bersagli di prova pubblici, pensati per essere testati

  [1]  http://testphp.vulnweb.com   Acunetix "vulnweb" (volutamente vulnerabile)
  [2]  https://demo.testfire.net    "Altoro Mutual", demo IBM/HCL
  [3]  https://badssl.com           casi di TLS/HTTPS buoni e cattivi

# Bersagli di prova locali (sul tuo computer)

  [4]  OWASP Juice Shop   in Docker, es. http://localhost:3000
       docker run --rm -p 3000:3000 bkimminich/juice-shop
"""

VULNERABILITY_ASSESSMENT = """\
# Vulnerability Assessment (passivo)

È la fase che ApocalypseStriker esegue oggi: sola lettura, non altera il
bersaglio. Contatta l'applicazione come un browser e osserva.

# Cosa controlla

  Header di sicurezza   HSTS, Content-Security-Policy, X-Content-Type-Options,
                        X-Frame-Options e simili: presenza e valore.
  Cookie                attributi Secure, HttpOnly e SameSite.
  TLS / HTTPS           versione del protocollo, redirect http->https, certificato.
  Tecnologie            server e framework dichiarati (es. nginx, PHP) e versione.
  CVE note              per prodotto e versione, cercate su NVD, pesate con KEV/EPSS.

! È tutto passivo: nessun payload, nessun attacco. Non vengono provate le
! vulnerabilità, solo rilevati gli indizi. La conferma attiva è il pentest.
"""

PENETRATION_TESTING = """\
# Penetration Testing (attivo)

La seconda fase del VAPT: confermare le vulnerabilità sollecitando il bersaglio
con richieste di prova. ApocalypseStriker la appoggia su OWASP ZAP.

  Spider + passive scan   ZAP naviga l'applicazione e osserva le risposte. Non
                          attacca: è come il Vulnerability Assessment, da dentro ZAP.
  Active scan             invia richieste di prova (payload) per confermare le
                          vulnerabilità. È l'unica parte che SOLLECITA il bersaglio.

! L'active scan è intrusivo e ad alto impatto: può generare molte richieste,
! inserire dati e lasciare tracce. È protetto da un SECONDO consenso dedicato,
! separato dall'autorizzazione iniziale, e va eseguito solo su sistemi tuoi o
! con autorizzazione scritta, in un ambiente di prova.

# Stato in questa versione

La fase attiva (ZAP) è una fase separata e richiede un daemon ZAP in esecuzione
(di norma in Docker). Oggi la scansione guidata (voce 6) esegue il solo
Vulnerability Assessment passivo; l'active scan arriverà come fase a sé.
"""

OPZIONI = """\
# Opzioni della riga di comando (apocalypse attack <url>)

--env AMBIENTE         ambiente dell'applicazione, scritto nel report
--format FORMATI       formati del report separati da virgola (vedi sotto)
--no-nvd               non cercare le CVE su NVD: prodotto e versione non escono
                       dalla macchina
--no-banner            non mostrare l'animazione del drago all'avvio
--output NOME          nome del report (default: web_<data-ora>)
--yes                  salta la conferma di autorizzazione (richiede --env)

# Formati e dove finiscono i report

--format md,json,csv   Markdown (leggibile), JSON (il modello completo), CSV (i
                       finding in tabella). Default: md.

I report finiscono nella cartella del progetto, una sottocartella per formato:

  reports/md/    reports/json/    reports/csv/

! Il report HTML del web non è ancora disponibile (arriverà con html_web):
! per ora i formati web sono md, json e csv.
"""


# --------------------------------------------------------------------------
# Esegui una scansione (voce operativa): costruisce ed esegue "apocalypse attack ..."
# --------------------------------------------------------------------------

# Combinazioni di formati offerte nella scansione guidata (solo quelli web)
FORMATI_PRESET = (
    (["md"], "solo Markdown (leggibile)"),
    (["md", "json"], "Markdown + JSON (il modello completo)"),
    (["md", "json", "csv"], "Markdown + JSON + CSV (finding in tabella)"),
)


def comando_web(url, ambiente, nvd, formati):
    """Il comando della scansione web. Lo esegue via "-m apocalypsescan_app.web.web_report"
    (modulo autonomo, non dipende da main.py); mai --yes, così la conferma di autorizzazione
    viene sempre chiesta dentro web_report. Restituisce (argv_da_eseguire, comando_mostrato)."""
    opzioni = ["--env", ambiente, "--format", ",".join(formati)] + ([] if nvd else ["--no-nvd"])
    argv = [sys.executable, "-m", "apocalypsescan_app.web.web_report", url, *opzioni]
    # ciò che l'utente può digitare da sé: il comando equivalente del programma installato
    mostrato = "apocalypse attack " + " ".join(shlex.quote(a) for a in [url, *opzioni])
    return argv, mostrato


def esegui_scansione():
    """Scansione guidata: chiede URL, ambiente, tipo di analisi, CVE e formati,
    costruisce il comando e, se richiesto, lo avvia (con la conferma di autorizzazione)."""
    titolo_sezione("ESEGUI UNA SCANSIONE - VULNERABILITY ASSESSMENT (PASSIVO)")
    print(c("Il drago punta l'applicazione, per ora con il solo sguardo: ricognizione", GRIGIO))
    print(c("PASSIVA di header, cookie, TLS, tecnologie e CVE note. Nessun payload.", GRIGIO))
    print(c("Ctrl+C in qualsiasi momento per annullare e tornare al menù.", GRIGIO))
    passo = Passi()

    passo("Applicazione")
    mostra_opzioni(("URL", "l'applicazione da analizzare (obbligatorio)"))
    print(c("Senza schema viene usato https:// (es. esempio.it -> https://esempio.it/).", GRIGIO))
    print()
    url = chiedi("Quale applicazione vuoi analizzare?", valida=valida_url)

    passo("Ambiente")
    mostra_opzioni(("--env AMBIENTE", "scritto nel report insieme all'autorizzazione"))
    ambiente = WEB_AMBIENTI[chiedi_scelta("In quale ambiente gira l'applicazione?",
                                          [(a, "") for a in WEB_AMBIENTI])]

    passo("Tipo di analisi")
    scelta = chiedi_scelta(
        "Quale analisi vuoi eseguire?",
        [("Solo Vulnerability Assessment (passivo)", "sola lettura, non tocca il bersaglio"),
         ("Anche Penetration Testing (attivo)", "active scan ZAP: intrusivo, secondo consenso")])
    if scelta == 1:
        print()
        avviso("La fase attiva (ZAP active scan) è una fase separata e richiede un daemon",
               "ZAP in esecuzione: non è ancora disponibile dalla scansione guidata.")
        print(c("Vedi la voce 4 del menù per come funziona e il doppio consenso.", GRIGIO))
        if not chiedi_si_no("\nProcedo intanto con il solo Vulnerability Assessment (passivo)?", True):
            print("\n" + c("Scansione annullata.", GRIGIO))
            pausa()
            return

    passo("CVE note")
    mostra_opzioni(("--no-nvd", "non cercare le CVE delle versioni su NVD"))
    print(c("Per le tecnologie con versione (es. nginx/1.10.3) le CVE si cercano su NVD:", GRIGIO))
    print(c("riceve solo prodotto e versione, mai l'URL analizzato.", GRIGIO))
    nvd = chiedi_si_no("Cercare le CVE note su NVD?", True)

    passo("Formati del report")
    mostra_opzioni(("--format FORMATI", "in quali formati salvare il report"))
    formati = FORMATI_PRESET[chiedi_scelta(
        "In quali formati vuoi il report?",
        [(", ".join(f), d) for f, d in FORMATI_PRESET])][0]

    url = normalizza_url(url)[0]
    argv, mostrato = comando_web(url, ambiente, nvd, formati)
    print()
    riga("-")
    print(f"{c('URL:', GRIGIO)}       {c(url, GRASSETTO)}")
    print(f"{c('Ambiente:', GRIGIO)}  {c(ambiente, GRASSETTO)}")
    print(f"{c('Formati:', GRIGIO)}   {c(', '.join(formati), GRASSETTO)}")
    print("\n" + c("Comando equivalente:", TITOLO) + "\n")
    print("  " + c(mostrato, AZIONE))
    riga("-")
    print(c("Prima di iniziare ti verrà chiesto di confermare l'autorizzazione.", TITOLO))

    if chiedi_si_no("\nLanciarlo adesso?"):
        print()
        try:
            subprocess.run(argv)
        except KeyboardInterrupt:
            print()
            avviso("Scansione interrotta.")
    else:
        print("\n" + c("Puoi copiare il comando e lanciarlo quando vuoi.", GRIGIO))
    pausa()


# --------------------------------------------------------------------------
# Intestazione e menù
# --------------------------------------------------------------------------

def intestazione():
    """Banner (wordmark APOCALYPSE) e sottotitolo STRIKER, mostrati all'apertura del menù."""
    righe = st.banner_righe()
    pulisci_schermo()
    print()
    print(st.banner_colorato(righe))
    larghezza = max(len(r) for r in righe)
    print(c(SOTTOTITOLO.center(larghezza).rstrip(), ACCENTO))
    print()
    print(f"  {c('ApocalypseStriker', GRASSETTO)}  {c(f'v{__version__}', ARANCIO)}")
    print(f"  {c(PRODOTTO, TITOLO)}")
    print()
    riga()


class Voce(NamedTuple):
    """Una voce del menù."""
    numero: str
    etichetta: str
    descrizione: str
    azione: object = None    # (titolo, testo) di una sezione della guida, una funzione, o None per uscire
    stile: str = ""          # "azione" o "esci": colore della voce


VOCI = [
    Voce("1", "Come funziona", "VA passivo + PT attivo, impatto x probabilità",
         ("COME FUNZIONA", COME_FUNZIONA)),
    Voce("2", "Prima di iniziare", "Autorizzazione e bersagli di prova",
         ("PRIMA DI INIZIARE", PRIMA_DI_INIZIARE)),
    Voce("3", "Vulnerability Assessment", "La scansione passiva: cosa controlla",
         ("VULNERABILITY ASSESSMENT (PASSIVO)", VULNERABILITY_ASSESSMENT)),
    Voce("4", "Penetration Testing", "La scansione attiva (ZAP) e il doppio consenso",
         ("PENETRATION TESTING (ATTIVO)", PENETRATION_TESTING)),
    Voce("5", "Opzioni e report", "Flag disponibili, formati e dove finiscono",
         ("OPZIONI E FORMATI DEL REPORT", OPZIONI)),
    Voce("6", "Esegui una scansione", "Scansione guidata su un URL", esegui_scansione, stile="azione"),
    Voce("0", "Esci", "", stile="esci"),
]


def mostra_menu():
    intestazione()
    print()
    largo_num = max(len(v.numero) for v in VOCI) + 2
    largo_etichetta = max(24, max(len(v.etichetta) for v in VOCI) + 2)
    for v in VOCI:
        if v.stile == "azione":
            colore = AZIONE
        elif v.stile == "esci":
            colore = GRIGIO
        else:
            colore = TITOLO
        numero = f"[{v.numero}]".ljust(largo_num)
        etichetta = f"{v.etichetta:<{largo_etichetta}}"
        print(f"    {c(numero, colore)}  {c(etichetta, colore if v.stile != 'esci' else GRIGIO)}"
              f"{c(v.descrizione, GRIGIO)}")
    print()
    print(f"  {c('Per saltare il menù:', GRIGIO)}  {c('apocalypse attack <url>', AZIONE)}")
    riga()


def esci():
    print("\n" + c("Alla prossima. Per riaprire il menù: ", GRIGIO) + c("apocalypse attack", AZIONE))
    return 0


def mostra_errore(voce, errore):
    """Messaggio leggibile per un'eccezione sollevata da una voce del menù."""
    print()
    avviso(f"{voce.etichetta} si è interrotta per un errore imprevisto:",
           f"{type(errore).__name__}: {errore}")
    print(c("Il menù resta aperto: puoi riprovare o scegliere un'altra voce.", GRIGIO))


def menu_principale():
    """Ciclo principale del menù. Esce con 0 oppure Ctrl+C."""
    while True:
        mostra_menu()
        try:
            scelta = input("\n  " + c("Scegli una voce:", GRASSETTO) + " ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return esci()

        voce = next((v for v in VOCI if v.numero == scelta), None)
        try:
            if voce is None:
                print()
                errore_input(f"Scelta non valida: {scelta!r}")
                pausa()
            elif voce.stile == "esci":
                return esci()
            elif callable(voce.azione):
                pulisci_schermo()
                try:
                    voce.azione()
                except (KeyboardInterrupt, EOFError):
                    print("\n\n" + c(f"{voce.etichetta} annullata.", AVVISO))
                except Exception as errore:   # un errore in una voce non chiude il menù
                    mostra_errore(voce, errore)
                    pausa()
            else:
                titolo, testo = voce.azione
                pulisci_schermo()
                titolo_sezione(titolo)
                print(colora_testo(testo))
                pausa()
        except (KeyboardInterrupt, EOFError):
            print()
            return esci()


if __name__ == "__main__":
    sys.exit(menu_principale())
