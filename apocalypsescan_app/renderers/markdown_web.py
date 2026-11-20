"""Renderer Markdown del report VAPT web (ricognizione passiva).

Stesso stile del renderer host (markdown.py): stessa "Tabella dei rischi", stessa
matrice Impatto x Probabilità, stesse note metodologiche. Cambiano le sezioni: qui la
ricognizione (tecnologie, TLS) e l'elenco dei finding con categoria OWASP, URL ed evidenza.
Lavora solo sul modello prodotto da web.web_report.build_web_model().
"""
from datetime import datetime

from ..config import (IMPACT_SCALE, OWASP, PROBABILITY_SCALE, WEB_VA_COPERTE,
                      WEB_VA_FUORI_PORTATA)
from ..risk import risk_level
from ..interno.analisi import VOCI as VOCI_INTERNE
from ..web.esito_pt import esito_di, fonte_di
from .common import (SCORED_LEVELS, conteggi_fonte, elemento, percent, righe_esiti,
                     thresholds_text)


def _cell(value):
    """Valore sicuro dentro una cella di tabella Markdown."""
    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _risk_cells(f):
    """Celle Impatto | Probabilità | Rischio | Livello di un finding."""
    if f["impact"] is None:
        return "- | - | - | Informativo"
    return f"{f['impact']} | {f['probability']} | **{f['score']}** | {f['level']}"


def _dettaglio(f):
    """Motivazione del finding, preceduta dai dati sulle minacce (come nel renderer host)."""
    tags = []
    if f.get("kev"):
        tags.append("**[KEV]**")
    if f.get("epss") is not None:
        tags.append(f"[EPSS {percent(f['epss'])}]")
    if f.get("probability_basis") == "cvss":
        tags.append("[probabilità da CVSS]")
    if f.get("esito_pt_nota"):
        tags.append(f"*Esito PT: {f['esito_pt_nota']}.*")
    return " ".join(tags + [f["reason"]])


def _stato_cve(t):
    """Cella "CVE note" della tabella delle tecnologie riconosciute."""
    if "cve" in t:
        return f"{len(t['cve'])} (`{t['cpe']}`)"
    if "cve_errore" in t:
        return f"non cercate: {t['cve_errore']}"
    if not t.get("mappato"):
        return "non cercate: prodotto non mappato su NVD"
    return "versione non dichiarata: non determinabili"


def _intestazione(lines, meta):
    web = meta.get("analisi_web", True)
    lines.append("# Report Automatico di VAPT Web\n" if web else
                 "# Report Automatico di Analisi Interna\n")
    data = datetime.fromisoformat(meta["generated_at"]).strftime("%Y-%m-%d %H:%M")
    lines.append(f"**Target analizzato:** {meta['target']}  ")
    lines.append(f"**Data e ora:** {data}  ")
    lines.append(f"**Attività:** {meta['mode']}  ")
    autorizzazione = meta.get("autorizzazione")
    if autorizzazione:
        confermata = datetime.fromisoformat(autorizzazione["confermata_il"]).strftime("%Y-%m-%d %H:%M")
        lines.append(f"**Ambiente:** {autorizzazione['ambiente']}  ")
        lines.append(f"**Autorizzazione:** confermata il {confermata} ({autorizzazione['modo']})  ")
    else:
        lines.append("**Ambiente / autorizzazione:** non registrati (report generato fuori dal flusso standard)  ")
    lines.append(f"**Host:** {meta['host']}  ")
    interna = meta.get("autorizzazione_interna")
    if interna:
        confermata = datetime.fromisoformat(interna["confermata_il"]).strftime("%Y-%m-%d %H:%M")
        lines.append(f"**Analisi interna:** {interna['host']} come `{interna['utente']}`, "
                     f"autorizzata il {confermata} ({interna['modo']})  ")
    if not web:
        pass        # niente stato HTTP: l'analisi è solo interna
    elif meta.get("http_error"):
        lines.append(f"**Stato HTTP:** richiesta non riuscita ({meta['http_error']})  ")
    else:
        stato = str(meta.get("http_status"))
        if meta.get("redirected"):
            stato += f" (redirect → {meta['final_url']})"
        if meta.get("upgraded_https"):
            stato += " [HTTP→HTTPS]"
        if meta.get("http_tls_unverified"):
            stato += " (letto senza verifica TLS: il client ha rifiutato certificato o protocollo)"
        lines.append(f"**Stato HTTP:** {stato}  ")
    lines.append(f"**Strumento:** {meta['tool']}\n")


def _ricognizione(lines, model):
    lines.append("## Ricognizione passiva (Vulnerability Assessment)\n")
    lines.append("Dati che il server dichiara da sé a una normale richiesta HTTP(S): nessun "
                 "payload inviato, nessuna sollecitazione del bersaglio.\n")

    lines.append("### Tecnologie esposte\n")
    tecnologie = model.get("tecnologie") or {}
    if tecnologie:
        lines.append("| Header | Valore |")
        lines.append("|---|---|")
        for header, valore in tecnologie.items():
            lines.append(f"| {_cell(header)} | {_cell(valore)} |")
    else:
        lines.append("Nessun header rivela tecnologia o versione.")
    lines.append("")

    lines.append("### Tecnologie riconosciute e CVE note\n")
    rilevate = model.get("tecnologie_rilevate") or []
    if rilevate:
        lines.append("| Prodotto | Versione | Fonte | CVE note (NVD) |")
        lines.append("|---|---|---|---|")
        for t in rilevate:
            versione = _cell(t.get("versione"))
            if t.get("distro"):
                versione += f" ({t['distro']})"
            lines.append(f"| {_cell(t['prodotto'])} | {versione} | {_cell(t['fonte'])} | "
                         f"{_cell(_stato_cve(t))} |")
    else:
        lines.append("Nessuna tecnologia riconoscibile da header, meta generator o cookie.")
    lines.append("")

    lines.append("### Configurazione TLS\n")
    tls = model.get("tls")
    if not tls:
        lines.append("Bersaglio su HTTP: nessuna configurazione TLS da ispezionare.\n")
    elif tls.get("error"):
        lines.append(f"Ispezione TLS non riuscita: `{tls['error']}`\n")
    else:
        protocolli = tls.get("protocolli") or {}
        lines.append("| Voce | Valore |")
        lines.append("|---|---|")
        lines.append(f"| Protocollo migliore | {_cell(tls.get('protocol'))} |")
        lines.append(f"| Cifrario | {_cell(tls.get('cipher'))} |")
        lines.append("| Versioni accettate | "
                     + _cell(", ".join(p for p, ok in protocolli.items() if ok) or None) + " |")
        lines.append("| Versioni rifiutate | "
                     + _cell(", ".join(p for p, ok in protocolli.items() if not ok) or None) + " |")
        if tls.get("non_verificati"):
            lines.append(f"| Non verificate | {_cell(', '.join(tls['non_verificati']))} "
                         "(non supportate dal client OpenSSL 3: assenza non dimostrata) |")
        if tls.get("cert_valido"):
            emittente = tls.get("cert_issuer") or {}
            lines.append("| Certificato | valido |")
            lines.append(f"| Emittente certificato | "
                         f"{_cell(emittente.get('organizationName') or emittente.get('commonName'))} |")
            giorni = tls.get("giorni_a_scadenza")
            scadenza = _cell(tls.get("not_after"))
            if giorni is not None:
                scadenza += f" (tra {giorni} giorni)"
            lines.append(f"| Scadenza certificato | {scadenza} |")
        else:
            stato = "non valido" if tls.get("cert_valido") is False else "non verificato"
            lines.append(f"| Certificato | {stato}: `{_cell(tls.get('cert_error'))}` |")
        lines.append("")


def _interno(lines, model):
    """Sezione dell'analisi interna: cosa è stato letto, con quali permessi, e lo stato di
    ogni voce (eseguita, parziale, non disponibile con il motivo)."""
    meta_int = (model.get("meta") or {}).get("interno")
    if not meta_int:
        return
    lines.append("## Analisi interna (accesso autorizzato, sola lettura)\n")
    lines.append("Analisi della macchina che ospita l'applicazione, fatta dall'interno con "
                 "credenziali autorizzate. Solo comandi di **lettura** da un elenco ammesso: nessuna "
                 "modifica, installazione o riavvio. Le credenziali e i valori dei segreti non "
                 "compaiono nel report.\n")
    sudo = {True: "disponibile", False: "non disponibile (alcune voci sono parziali)",
            None: "non verificato"}[meta_int.get("sudo")]
    lines.append("| Voce | Valore |")
    lines.append("|---|---|")
    lines.append(f"| Macchina | {_cell(meta_int.get('bersaglio') or meta_int.get('host'))} |")
    lines.append(f"| Connessione | {_cell(meta_int.get('connessione'))} |")
    lines.append(f"| sudo | {sudo} |")
    lines.append(f"| Codice analizzato | {_cell(meta_int.get('codice') or 'non indicato')} |")
    lines.append(f"| Comandi eseguiti | {_cell(meta_int.get('comandi_eseguiti', 0))} |")
    lines.append("")
    lines.append("| Controllo | Stato | Dettaglio |")
    lines.append("|---|---|---|")
    for voce, st in (meta_int.get("voci") or {}).items():
        stato = st.get("stato")
        if stato != "eseguito":
            stato = f"**{stato}**"
        lines.append(f"| {_cell(VOCI_INTERNE.get(voce, voce))} | {stato} | "
                     f"{_cell(st.get('dettaglio') or '-')} |")
    lines.append("")


def _tabella_rischi(lines, findings):
    scored = [f for f in findings if f["impact"] is not None]
    info_count = len(findings) - len(scored)

    lines.append("## Tabella dei rischi (Rischio = Impatto x Probabilità)\n")
    lines.append("Un'unica tabella per tutti i finding: analisi **esterna** (ricognizione passiva e "
                 "penetration testing) e analisi **interna** della macchina, valutati con lo stesso "
                 "modello e ordinati dal rischio più alto. Impatto e probabilità su scala 1-5, "
                 f"rischio da 1 a 25 ({thresholds_text()}). La colonna **Fonte** dice da quale analisi "
                 "viene il finding, la colonna **Esito PT** l'esito della verifica di penetration "
                 "testing.\n")

    lines.append("### Riepilogo per livello\n")
    lines.append("| Livello | Esterni | Interni | Totale |")
    lines.append("|---|---:|---:|---:|")
    for level in SCORED_LEVELS:
        esterni, interni = conteggi_fonte(findings, level)
        lines.append(f"| {level} | {esterni} | {interni} | {esterni + interni} |")
    info_interni = sum(1 for f in findings if f["impact"] is None and fonte_di(f) == "interno")
    lines.append(f"| Informativo (non valutati) | {info_count - info_interni} | {info_interni} | "
                 f"{info_count} |")
    lines.append("")

    esiti = righe_esiti(findings)
    if esiti:
        lines.append("### Esito della verifica di penetration testing\n")
        lines.append("| Esito PT | Finding | Significato |")
        lines.append("|---|---:|---|")
        for esito, n, significato in esiti:
            lines.append(f"| {esito} | {n} | {significato} |")
        lines.append("")

    lines.append("### Matrice di rischio\n")
    lines.append("Ogni cella riporta il punteggio (I x P) e, in grassetto, quanti finding vi ricadono.\n")
    lines.append("| Impatto \\ Probabilità | "
                 + " | ".join(f"{p} {PROBABILITY_SCALE[p]}" for p in range(1, 6)) + " |")
    lines.append("|---|" + "---|" * 5)
    for i in range(5, 0, -1):
        cells = []
        for p in range(1, 6):
            n = sum(1 for f in scored if f["impact"] == i and f["probability"] == p)
            score = i * p
            cells.append(f"{score} {risk_level(score)[0]} · **{n}**" if n else f"{score} {risk_level(score)[0]}")
        lines.append(f"| **{i} {IMPACT_SCALE[i]}** | " + " | ".join(cells) + " |")
    lines.append("\nLegenda: C = Critico, A = Alto, M = Medio, B = Basso.\n")

    lines.append("### Elenco dei finding\n")
    if not scored:
        lines.append("Nessun finding valutabile: le analisi eseguite non hanno rilevato debolezze. "
                     "L'assenza di finding non è una garanzia: vedi la portata dell'analisi.\n")
    else:
        lines.append("| # | Fonte | OWASP | Finding | Elemento | Impatto | Probabilità | Rischio | Livello | "
                     "Esito PT | Evidenza | Dettaglio |")
        lines.append("|---:|---|---|---|---|---:|---:|---:|---|---|---|---|")
        for n, f in enumerate(scored, 1):
            lines.append(f"| {n} | {fonte_di(f)} | {_cell(f.get('owasp'))} | {_cell(f['item'])} | "
                         f"{_cell(elemento(f))} | {_risk_cells(f)} | {esito_di(f)} | "
                         f"{_cell(f.get('evidence'))} | {_cell(_dettaglio(f))} |")
        lines.append("")

    informativi = [f for f in findings if f["impact"] is None]
    if informativi:
        lines.append("### Finding informativi\n")
        lines.append("| Fonte | Finding | Elemento | Esito PT | Dettaglio |")
        lines.append("|---|---|---|---|---|")
        for f in informativi:
            lines.append(f"| {fonte_di(f)} | {_cell(f['item'])} | {_cell(elemento(f))} | "
                         f"{esito_di(f)} | {_cell(_dettaglio(f))} |")
        lines.append("")


def _portata(lines, model):
    """Cosa è stato controllato e cosa resta fuori: un report senza finding in una categoria
    non coperta non vuol dire che l'applicazione ne sia priva. Se è stato eseguito anche il
    penetration testing attivo, le categorie provate con payload sono segnalate come tali."""
    tls = model.get("tls")
    pentest = (model.get("meta") or {}).get("pentest")
    categorie_pt = (pentest or {}).get("categorie", {})
    lines.append("## Portata dell'analisi\n")
    if pentest:
        lines.append("Questa analisi unisce la ricognizione **passiva** (header, cookie, TLS, banner: "
                     "debolezze di **configurazione**) e il **penetration testing attivo** (payload "
                     "inviati a parametri e form per confermare vulnerabilità sfruttabili). La tabella "
                     "indica, per ogni categoria OWASP, come è stata coperta.\n")
    else:
        lines.append("Questa analisi legge soltanto ciò che l'applicazione espone a una normale "
                     "richiesta (header, cookie, TLS, banner). Trova debolezze di **configurazione**; "
                     "le vulnerabilità che si manifestano solo inviando input costruiti apposta "
                     "(payload) restano fuori, per natura della fase passiva.\n")
    lines.append("| Categoria OWASP | Stato | Cosa riguarda |")
    lines.append("|---|---|---|")
    for chiave in sorted(OWASP):
        if chiave in categorie_pt:
            stato = "**testata (attivo, con payload)**"
            cosa = categorie_pt[chiave]
        elif chiave == "A02" and not tls:
            stato = "controllata (configurazione)"
            cosa = "applicazione servita su HTTP: nessun TLS da ispezionare (vedi finding \"senza HTTPS\")"
        elif chiave == "A02" and tls.get("error"):
            # la categoria è coperta, ma in questa scansione il TLS non è stato ispezionato
            stato = "**non controllata in questa scansione**"
            cosa = f"ispezione TLS non riuscita ({tls['error']})"
        elif chiave in WEB_VA_COPERTE:
            stato, cosa = "controllata (configurazione)", WEB_VA_COPERTE[chiave]
        else:
            stato, cosa = "**non testata**", WEB_VA_FUORI_PORTATA.get(chiave, "-")
        lines.append(f"| {OWASP[chiave]} | {stato} | {_cell(cosa)} |")
    lines.append("")
    if pentest:
        nota = ("> Nelle categorie **testate (attivo)** un finding è una vulnerabilità **confermata** "
                "con payload. L'assenza di finding non è però una garanzia assoluta: sono coperti i "
                "punti di input raggiunti dal crawler. Le categorie **non testate** non sono state "
                "cercate da questa scansione.")
        if pentest.get("troncato"):
            nota += (" ⚠️ La scansione attiva è stata **troncata** (tetto di punti o di richieste): "
                     "alcuni punti di input potrebbero non essere stati provati.")
        lines.append(nota + "\n")
    else:
        lines.append("> L'assenza di finding nelle categorie **non testate** non indica l'assenza di "
                     "vulnerabilità: non sono state cercate. Richiedono il penetration testing attivo, "
                     "una fase separata soggetta a un consenso dedicato (opzione `--pentest`).\n")


def _note(lines):
    lines.append("## Note metodologiche\n")
    lines.append("Per ogni finding **Rischio = Impatto x Probabilità** (scala 1-5, punteggio 1-25). "
                 f"Soglie: {thresholds_text()}.\n")
    lines.append("| Valore | Impatto (danno se sfruttato) | Probabilità (verosimiglianza) |")
    lines.append("|---:|---|---|")
    for v in range(1, 6):
        lines.append(f"| {v} | {IMPACT_SCALE[v]} | {PROBABILITY_SCALE[v]} |")
    lines.append("")
    lines.append("La ricognizione è **passiva**: legge header, cookie e TLS come farebbe un browser, "
                 "senza inviare payload. I valori sono euristici (definiti in "
                 "`apocalypsescan_app/config.py`, blocco VAPT web) e **non sostituiscono una verifica "
                 "manuale**. Il penetration testing attivo (OWASP ZAP) è una fase separata, soggetta a "
                 "una conferma dedicata.\n")
    lines.append("Le **CVE note** vengono dal National Vulnerability Database, cercate per il CPE "
                 "prodotto:versione letto nei banner (a NVD non arriva l'URL analizzato). La versione "
                 "dichiarata dal banner può non corrispondere a quella reale e i pacchetti delle "
                 "distribuzioni ricevono patch senza cambiare versione (backport): le CVE vanno "
                 "verificate. La probabilità viene da CISA KEV ed EPSS quando disponibili, altrimenti "
                 "dal vettore CVSS. Una versione nascosta o 0 CVE in NVD **non** provano l'assenza "
                 "di vulnerabilità.\n")


def render(model):
    """Restituisce il report Markdown web come stringa."""
    lines = []
    web = model["meta"].get("analisi_web", True)
    _intestazione(lines, model["meta"])
    lines.append("---\n")
    if web:
        _ricognizione(lines, model)
        lines.append("\n---\n")
    if model["meta"].get("interno"):
        _interno(lines, model)
        lines.append("\n---\n")
    _tabella_rischi(lines, model["findings"])
    lines.append("\n---\n")
    if web:
        _portata(lines, model)
        lines.append("\n---\n")
    _note(lines)
    return "\n".join(lines)
