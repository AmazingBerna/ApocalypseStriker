"""comando.py - Il comando `apocalypse inspect` e le opzioni comuni con `attack --inspect`.

  apocalypse inspect --host 192.0.2.10 --user auditor --key ~/.ssh/id_ed25519 --code /var/www/app
  apocalypse attack https://app.esempio.it --inspect --host ... --user ... --code ...

Credenziali:
- host, utente, chiave SSH e porta: argomenti OPPURE variabili d'ambiente
  (APOCALYPSE_SSH_HOST, APOCALYPSE_SSH_USER, APOCALYPSE_SSH_KEY);
- password di sudo e credenziali del database: SOLO variabili d'ambiente
  (APOCALYPSE_SUDO_PASSWORD, APOCALYPSE_DB_USER, APOCALYPSE_DB_PASSWORD, ...). Non esiste
  un'opzione per passarle: sulla riga di comando sarebbero visibili con `ps` e nella cronologia
  della shell. Il programma non le stampa mai: dice solo se sono presenti.
Senza --host (né APOCALYPSE_SSH_HOST) l'analisi gira sulla macchina locale.

Prima di partire chiede l'autorizzazione mostrando host, utente e data (--yes la salta).
"""
import argparse
import getpass
import os
from datetime import datetime
from pathlib import Path

from ..config import (INT_ENV_DB_PASSWORD, INT_ENV_DB_USER, INT_ENV_SSH_HOST, INT_ENV_SSH_KEY,
                      INT_ENV_SSH_USER, INT_ENV_SUDO_PASSWORD, WEB_AMBIENTI)
from ..remote import LocalExecutor, SSHExecutor
from .analisi import VOCI, analisi_interna, riepilogo_stato
from .comandi import PERCORSO, EsecutoreSolaLettura

MODE_INT = "Analisi interna (accesso autorizzato alla macchina, sola lettura)"
TOOL_INT = "ApocalypseStriker inspect (sola lettura, elenco ammesso di comandi)"


class ErroreParametri(ValueError):
    """Parametri di connessione mancanti o non validi: il messaggio dice come rimediare."""


def aggiungi_opzioni(parser, con_flag_inspect=False):
    """Opzioni dell'analisi interna. con_flag_inspect: aggiunge --inspect (per attack)."""
    gruppo = parser.add_argument_group(
        "analisi interna",
        "Accesso autorizzato alla macchina che ospita l'applicazione, in sola lettura. "
        f"Password di sudo e credenziali del database SOLO da variabili d'ambiente "
        f"({INT_ENV_SUDO_PASSWORD}, {INT_ENV_DB_USER}, {INT_ENV_DB_PASSWORD}).")
    if con_flag_inspect:
        gruppo.add_argument("--inspect", action="store_true",
                            help="Esegue anche l'analisi INTERNA della macchina (report unico)")
    gruppo.add_argument("--host", default=None,
                        help=f"Host SSH della macchina (default: {INT_ENV_SSH_HOST}; senza host: "
                             "macchina locale)")
    gruppo.add_argument("--user", default=None, help=f"Utente SSH (default: {INT_ENV_SSH_USER})")
    gruppo.add_argument("--key", default=None,
                        help=f"Chiave privata SSH, solo il percorso (default: {INT_ENV_SSH_KEY})")
    gruppo.add_argument("--port", type=int, default=22, help="Porta SSH (default: 22)")
    gruppo.add_argument("--code", default=None,
                        help="Percorso ASSOLUTO del codice sorgente sulla macchina, per l'analisi "
                             "statica (es. /var/www/app)")
    gruppo.add_argument("--semgrep-rules", default=None,
                        help="Regole Semgrep LOCALI sulla macchina (percorso assoluto). Senza, "
                             "Semgrep non viene usato: mai regole scaricate da internet")
    return gruppo


def opzioni_interne_usate(args):
    return any(getattr(args, a, None) for a in ("host", "user", "key", "code", "semgrep_rules"))


def parametri_connessione(args, env=None):
    """{host, user, key, port}: dagli argomenti, poi dalle variabili d'ambiente.
    host None = macchina locale. Solleva ErroreParametri con un messaggio guidato."""
    env = os.environ if env is None else env
    host = args.host or env.get(INT_ENV_SSH_HOST) or None
    user = args.user or env.get(INT_ENV_SSH_USER) or None
    key = args.key or env.get(INT_ENV_SSH_KEY) or None
    if args.code is not None and not PERCORSO.accetta(args.code):
        raise ErroreParametri("--code deve essere un percorso assoluto sulla macchina analizzata "
                              "(es. /var/www/app), senza '..' né spazi")
    if args.semgrep_rules is not None and not PERCORSO.accetta(args.semgrep_rules):
        raise ErroreParametri("--semgrep-rules deve essere un percorso assoluto sulla macchina "
                              "analizzata: Semgrep usa solo regole locali")
    if host is None:
        return {"host": None, "user": getpass.getuser(), "key": None, "port": None}
    if not user:
        raise ErroreParametri(f"indica l'utente SSH con --user o con la variabile {INT_ENV_SSH_USER}")
    if key:
        percorso = Path(key).expanduser()
        if not percorso.is_file():
            raise ErroreParametri(f"chiave SSH non trovata: {percorso}")
        key = str(percorso)
    return {"host": host, "user": user, "key": key, "port": args.port}


def crea_esecutore(conn, env=None):
    """L'EsecutoreSolaLettura sopra SSHExecutor (o LocalExecutor senza host).
    La password di sudo viene letta solo dalla variabile d'ambiente."""
    env = os.environ if env is None else env
    if conn["host"] is None:
        return EsecutoreSolaLettura(LocalExecutor())
    try:
        ssh = SSHExecutor(conn["host"], conn["user"], port=conn["port"], key=conn["key"],
                          sudo_password=env.get(INT_ENV_SUDO_PASSWORD) or None)
    except ValueError as e:
        raise ErroreParametri(str(e)) from None
    return EsecutoreSolaLettura(ssh)


def descrizione_bersaglio(conn, esecutore):
    if conn["host"] is None:
        return f"locale: {esecutore.label}"
    return f"ssh://{conn['user']}@{conn['host']}:{conn['port']}"


def _leggi(domanda, leggi):
    try:
        return leggi(domanda)
    except (EOFError, KeyboardInterrupt):
        print("\nConferma non ricevuta. Uscita.")
        raise SystemExit(0)


def confirm_inspect(conn, esecutore, codice=None, skip=False, env=None, leggi=input):
    """Prompt di autorizzazione dell'analisi interna: host, utente e data. Delle credenziali
    dice solo SE sono presenti, mai il valore. Restituisce i dati da scrivere nel report."""
    env = os.environ if env is None else env
    momento = datetime.now()
    host = conn["host"] or esecutore.label
    print("=" * 70)
    print("AUTORIZZAZIONE - ANALISI INTERNA")
    print("ApocalypseStriker sta per ACCEDERE alla macchina con credenziali e leggerne, in")
    print("SOLA LETTURA, processi, servizi, database, configurazione e codice sorgente.")
    print("Nessuna modifica, installazione o riavvio: solo i comandi dell'elenco ammesso.")
    print(f"  Host:      {host}" + (f" (porta {conn['port']})" if conn["host"] else ""))
    print(f"  Utente:    {conn['user']}")
    print(f"  Data:      {momento.strftime('%Y-%m-%d %H:%M')}")
    if conn["host"]:
        print(f"  Chiave:    {conn['key'] or 'quella predefinita di ssh / agent'}")
    print(f"  Codice:    {codice or 'non indicato (niente analisi statica)'}")
    print(f"  Database:  credenziali {'presenti' if env.get(INT_ENV_DB_USER) else 'assenti'} "
          f"nelle variabili d'ambiente")
    print(f"  sudo:      password {'presente' if env.get(INT_ENV_SUDO_PASSWORD) else 'assente'} "
          "nelle variabili d'ambiente")
    print("La macchina dev'essere tua o con autorizzazione SCRITTA ad analizzarla.")
    print("=" * 70)
    if not skip:
        risposta = _leggi("Confermi di essere autorizzato ad accedere a questa macchina? "
                          "[scrivi 'si' per continuare]: ", leggi)
        if risposta.strip().lower() not in ("si", "sì", "yes", "y"):
            print("Conferma non ricevuta. Uscita.")
            raise SystemExit(0)
    return {"host": host, "utente": conn["user"],
            "confermata_il": momento.isoformat(timespec="seconds"),
            "modo": "non interattiva, --yes" if skip else "interattiva"}


def fasi_interne():
    return [f"int_{v}" for v in VOCI]


def main(argv=None):
    # import qui: web_report importa questo modulo per attack --inspect
    from .. import banner
    from ..progress import ProgressTracker
    from ..web import web_report

    parser = argparse.ArgumentParser(
        prog="apocalypse inspect",
        description="Analisi INTERNA della macchina che ospita l'applicazione: processi e servizi, "
                    "database, codice sorgente, web server, pacchetti. Sola lettura.")
    aggiungi_opzioni(parser)
    parser.add_argument("--env", choices=WEB_AMBIENTI, default=None,
                        help="Ambiente della macchina (se manca viene chiesto; obbligatorio con --yes)")
    parser.add_argument("--format", default="md",
                        help="Formati del report separati da virgola: md, html, json, csv (default: md)")
    parser.add_argument("--output", default=None, help="Nome del report (default: inspect_<timestamp>)")
    parser.add_argument("--yes", action="store_true",
                        help="Salta la richiesta interattiva di conferma dell'autorizzazione")
    parser.add_argument("--no-nvd", action="store_true",
                        help="Non cercare su NVD le CVE dei pacchetti installati")
    parser.add_argument("--interpreta", action="store_true",
                        help="Genera anche la spiegazione guidata dei risultati")
    parser.add_argument("--no-banner", action="store_true", help="Non mostrare l'animazione iniziale")
    args = parser.parse_args(argv)
    if args.yes and args.env is None:
        parser.error("con --yes l'ambiente va indicato con --env: il report non può esserne privo")
    try:
        conn = parametri_connessione(args)
        esecutore = crea_esecutore(conn)
    except ErroreParametri as e:
        parser.error(str(e))

    if not args.no_banner:
        banner.intro(form=banner.RISVEGLIO)
    ambiente = args.env or web_report.chiedi_ambiente()
    autorizzazione = confirm_inspect(conn, esecutore, args.code, skip=args.yes)

    progress = ProgressTracker(fasi_interne() + ["report"])
    progress.start()
    findings, meta_int = analisi_interna(esecutore, codice=args.code,
                                         semgrep_rules=args.semgrep_rules, nvd=not args.no_nvd,
                                         progress=progress)
    target = descrizione_bersaglio(conn, esecutore)
    meta_int["bersaglio"] = target
    model = web_report.build_web_model({"host": autorizzazione["host"], "target": target},
                                       findings, mode=MODE_INT)
    model["meta"].update(analisi_web=False, tool=TOOL_INT, interno=meta_int,
                         autorizzazione={"ambiente": ambiente, **autorizzazione})
    nome = args.output or f"inspect_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    progress.begin("report", "Generazione report")
    percorsi, lettura = web_report.scrivi_report(model, web_report.parse_formati_web(args.format),
                                                 nome, args.interpreta)
    progress.end()
    progress.finish()

    if meta_int.get("connessione") != "ok":
        print(f"\n[ERRORE] {meta_int.get('connessione')}")
    print("\nStato dell'analisi interna:")
    for riga in riepilogo_stato(meta_int):
        print(f"  - {riga}")
    web_report.stampa_esito(model, percorsi, lettura, nome)
    return 0 if meta_int.get("connessione") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
