"""Renderer HTML del report VAPT web.

Stesso contenuto del report Markdown (markdown_web.py): intestazione, ricognizione, tabella
e matrice dei rischi, portata dell'analisi e note metodologiche. In più, se gli si passa la
lettura dell'interprete (web.interprete_web), la sezione "Spiegazione guidata" con le schede
cosa significa / come viene attaccata / cosa fare.

Il file è autonomo: CSS interno, nessuno script e nessuna risorsa esterna (font, CDN,
immagini), così si apre anche offline. Ogni valore che viene dal bersaglio (header, URL,
evidenze con i payload del pentest) passa da html.escape: il report non esegue nulla.
Lavora solo sul modello prodotto da web.web_report.build_web_model().
"""
from datetime import datetime
from html import escape

from ..config import (IMPACT_SCALE, OWASP, PROBABILITY_SCALE, WEB_VA_COPERTE,
                      WEB_VA_FUORI_PORTATA)
from ..risk import risk_level
from .common import SCORED_LEVELS, percent, thresholds_text

# Classe CSS di ogni livello di rischio
CLASSE_LIVELLO = {"Critico": "critico", "Alto": "alto", "Medio": "medio", "Basso": "basso",
                  "Informativo": "info", "Nessuno": "info"}

CSS = """
:root {
  --sfondo: #fbf7fa; --carta: #ffffff; --testo: #1f1a1e; --tenue: #6b6169; --bordo: #e6dbe3;
  --accento: #c2187a; --accento-tenue: #fbe3f1; --codice: #f4eef2;
  --critico: #b3121f; --alto: #d4570b; --medio: #a87f00; --basso: #2e7d32; --info: #6b6169;
}
@media (prefers-color-scheme: dark) {
  :root {
    --sfondo: #151214; --carta: #1e1a1d; --testo: #eee6ec; --tenue: #a99fa7; --bordo: #3a3238;
    --accento: #ff5cb8; --accento-tenue: #3a1c2e; --codice: #2a2428;
    --critico: #ff6b6b; --alto: #ff9b52; --medio: #f2c94c; --basso: #6fcf73; --info: #a99fa7;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--sfondo); color: var(--testo);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 24px 16px 64px; }
header.testata { border-bottom: 3px solid var(--accento); margin-bottom: 24px; padding-bottom: 12px; }
header.testata h1 { margin: 0 0 4px; color: var(--accento); font-size: 1.7rem; }
h2 { margin-top: 40px; padding-bottom: 6px; border-bottom: 1px solid var(--bordo); }
h3 { margin-top: 28px; }
.dati { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; }
.dati dt { color: var(--tenue); }
.dati dd { margin: 0; overflow-wrap: anywhere; }
.tenue { color: var(--tenue); }
.scorre { overflow-x: auto; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; background: var(--carta); font-size: 0.92rem; }
th, td { border: 1px solid var(--bordo); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: var(--accento-tenue); }
td.num, th.num { text-align: right; white-space: nowrap; }
td.lungo { overflow-wrap: anywhere; min-width: 14em; }
code { background: var(--codice); padding: 1px 4px; border-radius: 4px; font-size: 0.88em;
  overflow-wrap: anywhere; }
.livello { display: inline-block; padding: 1px 8px; border-radius: 999px; font-weight: 600;
  font-size: 0.85rem; color: #fff; white-space: nowrap; }
.livello.critico { background: var(--critico); } .livello.alto { background: var(--alto); }
.livello.medio { background: var(--medio); } .livello.basso { background: var(--basso); }
.livello.info { background: var(--info); }
.kev { color: var(--critico); font-weight: 700; }
table.matrice td { text-align: center; white-space: nowrap; }
table.matrice td.critico { background: color-mix(in srgb, var(--critico) 22%, transparent); }
table.matrice td.alto { background: color-mix(in srgb, var(--alto) 22%, transparent); }
table.matrice td.medio { background: color-mix(in srgb, var(--medio) 22%, transparent); }
table.matrice td.basso { background: color-mix(in srgb, var(--basso) 22%, transparent); }
.nota { border-left: 4px solid var(--accento); background: var(--carta); padding: 10px 14px; margin: 14px 0; }
.verdetto { font-size: 1.1rem; font-weight: 600; padding: 12px 16px; border-radius: 8px;
  background: var(--carta); border-left: 6px solid var(--info); }
.verdetto.critico { border-color: var(--critico); } .verdetto.alto { border-color: var(--alto); }
.verdetto.medio { border-color: var(--medio); } .verdetto.basso { border-color: var(--basso); }
.scheda { background: var(--carta); border: 1px solid var(--bordo); border-radius: 8px;
  padding: 14px 18px; margin: 14px 0; }
.scheda h4 { margin: 0 0 6px; font-size: 1.05rem; }
.scheda .sotto { color: var(--tenue); font-size: 0.88rem; margin-bottom: 10px; }
.scheda dl { margin: 0; }
.scheda dt { font-weight: 700; margin-top: 8px; }
.scheda dd { margin: 2px 0 0; }
.scheda dd.fare { color: var(--accento); font-weight: 600; }
footer { margin-top: 48px; color: var(--tenue); font-size: 0.85rem; }
"""


def _e(valore):
    """Testo sicuro in HTML; None diventa un trattino."""
    return "-" if valore is None else escape(str(valore))


def _livello(livello):
    return f'<span class="livello {CLASSE_LIVELLO.get(livello, "info")}">{_e(livello)}</span>'


def _tabella(intestazioni, righe, classi=None, classe_tabella=""):
    """Tabella HTML; intestazioni e celle sono già HTML. classi: classe CSS per colonna."""
    classi = classi or [""] * len(intestazioni)
    attr = f' class="{classe_tabella}"' if classe_tabella else ""
    testa = "".join(f'<th class="{c}">{h}</th>' if c else f"<th>{h}</th>"
                    for h, c in zip(intestazioni, classi))
    corpo = "".join("<tr>" + "".join(f'<td class="{c}">{v}</td>' if c else f"<td>{v}</td>"
                                     for v, c in zip(riga, classi)) + "</tr>" for riga in righe)
    return f'<div class="scorre"><table{attr}><thead><tr>{testa}</tr></thead><tbody>{corpo}</tbody></table></div>'


def _data(iso):
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return _e(iso)


# --------------------------------------------------------------------------
# Sezioni del report (stesso contenuto di markdown_web)
# --------------------------------------------------------------------------

def _intestazione(meta):
    dati = [("Target analizzato", _e(meta.get("target"))),
            ("Data e ora", _data(meta.get("generated_at"))),
            ("Attività", _e(meta.get("mode")))]
    autorizzazione = meta.get("autorizzazione")
    if autorizzazione:
        dati.append(("Ambiente", _e(autorizzazione.get("ambiente"))))
        dati.append(("Autorizzazione", f"confermata il {_data(autorizzazione.get('confermata_il'))} "
                                       f"({_e(autorizzazione.get('modo'))})"))
    else:
        dati.append(("Ambiente / autorizzazione",
                     "non registrati (report generato fuori dal flusso standard)"))
    dati.append(("Host", _e(meta.get("host"))))
    if meta.get("http_error"):
        dati.append(("Stato HTTP", f"richiesta non riuscita ({_e(meta['http_error'])})"))
    else:
        stato = _e(meta.get("http_status"))
        if meta.get("redirected"):
            stato += f" (redirect → {_e(meta.get('final_url'))})"
        if meta.get("upgraded_https"):
            stato += " [HTTP→HTTPS]"
        if meta.get("http_tls_unverified"):
            stato += " (letto senza verifica TLS: il client ha rifiutato certificato o protocollo)"
        dati.append(("Stato HTTP", stato))
    dati.append(("Strumento", _e(meta.get("tool"))))
    righe = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in dati)
    return ('<header class="testata"><h1>Report Automatico di VAPT Web</h1>'
            '<div class="tenue">ApocalypseStriker · Vulnerability Assessment + Penetration Testing</div>'
            f'</header><dl class="dati">{righe}</dl>')


def _stato_cve(t):
    if "cve" in t:
        return f"{len(t['cve'])} (<code>{_e(t.get('cpe'))}</code>)"
    if "cve_errore" in t:
        return f"non cercate: {_e(t['cve_errore'])}"
    if not t.get("mappato"):
        return "non cercate: prodotto non mappato su NVD"
    return "versione non dichiarata: non determinabili"


def _ricognizione(model):
    parti = ["<h2>Ricognizione passiva (Vulnerability Assessment)</h2>",
             '<p class="tenue">Dati che il server dichiara da sé a una normale richiesta HTTP(S): '
             "nessun payload inviato, nessuna sollecitazione del bersaglio.</p>",
             "<h3>Tecnologie esposte</h3>"]
    tecnologie = model.get("tecnologie") or {}
    if tecnologie:
        parti.append(_tabella(["Header", "Valore"],
                              [(_e(h), f"<code>{_e(v)}</code>") for h, v in tecnologie.items()]))
    else:
        parti.append("<p>Nessun header rivela tecnologia o versione.</p>")

    parti.append("<h3>Tecnologie riconosciute e CVE note</h3>")
    rilevate = model.get("tecnologie_rilevate") or []
    if rilevate:
        righe = []
        for t in rilevate:
            versione = _e(t.get("versione")) + (f" ({_e(t['distro'])})" if t.get("distro") else "")
            righe.append((_e(t.get("prodotto")), versione, _e(t.get("fonte")), _stato_cve(t)))
        parti.append(_tabella(["Prodotto", "Versione", "Fonte", "CVE note (NVD)"], righe))
    else:
        parti.append("<p>Nessuna tecnologia riconoscibile da header, meta generator o cookie.</p>")

    parti.append("<h3>Configurazione TLS</h3>")
    tls = model.get("tls")
    if not tls:
        parti.append("<p>Bersaglio su HTTP: nessuna configurazione TLS da ispezionare.</p>")
    elif tls.get("error"):
        parti.append(f"<p>Ispezione TLS non riuscita: <code>{_e(tls['error'])}</code></p>")
    else:
        protocolli = tls.get("protocolli") or {}
        righe = [("Protocollo migliore", _e(tls.get("protocol"))),
                 ("Cifrario", _e(tls.get("cipher"))),
                 ("Versioni accettate", _e(", ".join(p for p, ok in protocolli.items() if ok) or None)),
                 ("Versioni rifiutate", _e(", ".join(p for p, ok in protocolli.items() if not ok) or None))]
        if tls.get("non_verificati"):
            righe.append(("Non verificate", f"{_e(', '.join(tls['non_verificati']))} (non supportate "
                                            "dal client OpenSSL 3: assenza non dimostrata)"))
        if tls.get("cert_valido"):
            emittente = tls.get("cert_issuer") or {}
            scadenza = _e(tls.get("not_after"))
            if tls.get("giorni_a_scadenza") is not None:
                scadenza += f" (tra {_e(tls['giorni_a_scadenza'])} giorni)"
            righe += [("Certificato", "valido"),
                      ("Emittente certificato",
                       _e(emittente.get("organizationName") or emittente.get("commonName"))),
                      ("Scadenza certificato", scadenza)]
        else:
            stato = "non valido" if tls.get("cert_valido") is False else "non verificato"
            righe.append(("Certificato", f"{stato}: <code>{_e(tls.get('cert_error'))}</code>"))
        parti.append(_tabella(["Voce", "Valore"], righe))
    return "".join(parti)


def _dettaglio(f):
    """Motivazione del finding, preceduta dai dati sulle minacce (come nel Markdown)."""
    tag = []
    if f.get("kev"):
        tag.append('<span class="kev">[KEV]</span>')
    if f.get("epss") is not None:
        tag.append(f"[EPSS {_e(percent(f['epss']))}]")
    if f.get("probability_basis") == "cvss":
        tag.append("[probabilità da CVSS]")
    return " ".join(tag + [_e(f.get("reason"))])


def _tabella_rischi(findings):
    scored = [f for f in findings if f.get("impact") is not None]
    informativi = [f for f in findings if f.get("impact") is None]
    parti = ["<h2>Tabella dei rischi (Rischio = Impatto x Probabilità)</h2>",
             "<p>Finding valutati con lo stesso modello della serie e ordinati dal rischio più alto. "
             "Impatto e probabilità su scala 1-5, rischio da 1 a 25 "
             f"({_e(thresholds_text())}).</p>",
             "<h3>Riepilogo per livello</h3>"]
    righe = [(_livello(lv), str(sum(1 for f in scored if f["level"] == lv))) for lv in SCORED_LEVELS]
    righe.append(("Informativo (non valutati)", str(len(informativi))))
    parti.append(_tabella(["Livello", "Finding"], righe, ["", "num"]))

    parti.append("<h3>Matrice di rischio</h3>")
    parti.append('<p class="tenue">Ogni cella riporta il punteggio (I x P) e, in grassetto, '
                 "quanti finding vi ricadono.</p>")
    righe = []
    for i in range(5, 0, -1):
        celle = [f"<strong>{i} {_e(IMPACT_SCALE[i])}</strong>"]
        for p in range(1, 6):
            n = sum(1 for f in scored if f["impact"] == i and f["probability"] == p)
            punteggio = i * p
            testo = f"{punteggio} {risk_level(punteggio)[0]}" + (f" · <strong>{n}</strong>" if n else "")
            celle.append((testo, CLASSE_LIVELLO.get(risk_level(punteggio), "")))
        righe.append(celle)
    testa = "".join(f"<th>{p} {_e(PROBABILITY_SCALE[p])}</th>" for p in range(1, 6))
    corpo = "".join("<tr><th>" + r[0] + "</th>"
                    + "".join(f'<td class="{c}">{t}</td>' for t, c in r[1:]) + "</tr>" for r in righe)
    parti.append('<div class="scorre"><table class="matrice"><thead><tr><th>Impatto \\ Probabilità</th>'
                 f"{testa}</tr></thead><tbody>{corpo}</tbody></table></div>")
    parti.append('<p class="tenue">Legenda: C = Critico, A = Alto, M = Medio, B = Basso.</p>')

    parti.append("<h3>Elenco dei finding</h3>")
    if not scored:
        parti.append("<p>Nessun finding valutabile: la ricognizione passiva non ha rilevato debolezze di "
                     "<strong>configurazione</strong>. Non dice nulla sulle vulnerabilità che richiedono "
                     "payload: vedi <em>Portata dell'analisi</em>.</p>")
    else:
        righe = []
        for n, f in enumerate(scored, 1):
            righe.append((str(n), _e(f.get("owasp")), _e(f.get("item")), f"<code>{_e(f.get('url'))}</code>",
                          str(f["impact"]), str(f["probability"]), f"<strong>{f['score']}</strong>",
                          _livello(f["level"]), f"<code>{_e(f.get('evidence'))}</code>", _dettaglio(f)))
        parti.append(_tabella(
            ["#", "OWASP", "Finding", "URL", "Impatto", "Probabilità", "Rischio", "Livello",
             "Evidenza", "Dettaglio"], righe,
            ["num", "", "", "lungo", "num", "num", "num", "", "lungo", "lungo"]))

    if informativi:
        parti.append("<h3>Finding informativi</h3>")
        parti.append(_tabella(["Finding", "Dettaglio"],
                              [(_e(f.get("item")), _e(f.get("reason"))) for f in informativi],
                              ["", "lungo"]))
    return "".join(parti)


def _portata(model):
    tls = model.get("tls")
    pentest = (model.get("meta") or {}).get("pentest")
    categorie_pt = (pentest or {}).get("categorie", {})
    parti = ["<h2>Portata dell'analisi</h2>"]
    if pentest:
        parti.append("<p>Questa analisi unisce la ricognizione <strong>passiva</strong> (header, cookie, "
                     "TLS, banner: debolezze di <strong>configurazione</strong>) e il <strong>penetration "
                     "testing attivo</strong> (payload inviati a parametri e form per confermare "
                     "vulnerabilità sfruttabili). La tabella indica, per ogni categoria OWASP, come è "
                     "stata coperta.</p>")
    else:
        parti.append("<p>Questa analisi legge soltanto ciò che l'applicazione espone a una normale "
                     "richiesta (header, cookie, TLS, banner). Trova debolezze di <strong>configurazione"
                     "</strong>; le vulnerabilità che si manifestano solo inviando input costruiti "
                     "apposta (payload) restano fuori, per natura della fase passiva.</p>")
    righe = []
    for chiave in sorted(OWASP):
        if chiave in categorie_pt:
            stato, cosa = "<strong>testata (attivo, con payload)</strong>", categorie_pt[chiave]
        elif chiave == "A02" and not tls:
            stato = "controllata (configurazione)"
            cosa = 'applicazione servita su HTTP: nessun TLS da ispezionare (vedi finding "senza HTTPS")'
        elif chiave == "A02" and tls.get("error"):
            stato, cosa = ("<strong>non controllata in questa scansione</strong>",
                           f"ispezione TLS non riuscita ({tls['error']})")
        elif chiave in WEB_VA_COPERTE:
            stato, cosa = "controllata (configurazione)", WEB_VA_COPERTE[chiave]
        else:
            stato, cosa = "<strong>non testata</strong>", WEB_VA_FUORI_PORTATA.get(chiave, "-")
        righe.append((_e(OWASP[chiave]), stato, _e(cosa)))
    parti.append(_tabella(["Categoria OWASP", "Stato", "Cosa riguarda"], righe))
    if pentest:
        nota = ("Nelle categorie <strong>testate (attivo)</strong> un finding è una vulnerabilità "
                "<strong>confermata</strong> con payload. L'assenza di finding non è però una garanzia "
                "assoluta: sono coperti i punti di input raggiunti dal crawler. Le categorie <strong>non "
                "testate</strong> non sono state cercate da questa scansione.")
        if pentest.get("troncato"):
            nota += (" La scansione attiva è stata <strong>troncata</strong> (tetto di punti o di "
                     "richieste): alcuni punti di input potrebbero non essere stati provati.")
    else:
        nota = ("L'assenza di finding nelle categorie <strong>non testate</strong> non indica l'assenza "
                "di vulnerabilità: non sono state cercate. Richiedono il penetration testing attivo, una "
                "fase separata soggetta a un consenso dedicato (opzione <code>--pentest</code>).")
    parti.append(f'<div class="nota">{nota}</div>')
    return "".join(parti)


def _note():
    righe = [(str(v), _e(IMPACT_SCALE[v]), _e(PROBABILITY_SCALE[v])) for v in range(1, 6)]
    return ("<h2>Note metodologiche</h2>"
            "<p>Per ogni finding <strong>Rischio = Impatto x Probabilità</strong> (scala 1-5, punteggio "
            f"1-25). Soglie: {_e(thresholds_text())}.</p>"
            + _tabella(["Valore", "Impatto (danno se sfruttato)", "Probabilità (verosimiglianza)"],
                       righe, ["num", "", ""])
            + "<p>La ricognizione passiva legge header, cookie e TLS come farebbe un browser, senza "
              "inviare payload; il penetration testing attivo è una fase separata, soggetta a una "
              "conferma dedicata. I valori sono euristici (definiti in "
              "<code>apocalypsescan_app/config.py</code>, blocco VAPT web) e <strong>non sostituiscono "
              "una verifica manuale</strong>.</p>"
              "<p>Le <strong>CVE note</strong> vengono dal National Vulnerability Database, cercate per il "
              "CPE prodotto:versione letto nei banner (a NVD non arriva l'URL analizzato). La versione "
              "dichiarata dal banner può non corrispondere a quella reale e i pacchetti delle "
              "distribuzioni ricevono patch senza cambiare versione (backport): le CVE vanno verificate. "
              "La probabilità viene da CISA KEV ed EPSS quando disponibili, altrimenti dal vettore CVSS. "
              "Una versione nascosta o 0 CVE in NVD <strong>non</strong> provano l'assenza di "
              "vulnerabilità.</p>")


# --------------------------------------------------------------------------
# Spiegazione guidata (lettura di web.interprete_web)
# --------------------------------------------------------------------------

def _sottotitolo(s):
    parti = [_livello(s["livello"]) + (f" {_e(s['score'])}" if s.get("perche") else "")]
    if s.get("kev"):
        parti.append('<span class="kev">KEV</span>')
    parti.append(_e(s.get("nome_tipo")))
    if s.get("owasp"):
        parti.append(_e(OWASP.get(s["owasp"], s["owasp"])))
    parti.append("attivo" if s.get("attivo") else "passivo")
    parti.append(f"<code>{_e(s.get('url'))}</code>")
    return " · ".join(parti)


def _scheda(s, titolo, con_perche=True):
    voci = [("Cosa significa", s.get("cosa_significa"), ""),
            ("Come viene attaccata", s.get("come_attaccano"), ""),
            ("Cosa fare", s.get("cosa_fare"), "fare")]
    if con_perche and s.get("perche"):
        voci.append(("Perché questo livello", f"{s['perche']} {s.get('urgenza') or ''}".strip(), ""))
    corpo = "".join(f'<dt>{k}</dt><dd class="{c}">{_e(v)}</dd>' if c else f"<dt>{k}</dt><dd>{_e(v)}</dd>"
                    for k, v, c in voci)
    if s.get("evidenza"):
        corpo += f"<dt>Evidenza</dt><dd><code>{_e(s['evidenza'])}</code></dd>"
    return (f'<div class="scheda"><h4>{titolo}</h4><div class="sotto">{_sottotitolo(s)}</div>'
            f"<dl>{corpo}</dl></div>")


def _spiegazione(lettura):
    verdetto = lettura["verdetto"]
    parti = ['<h2 id="spiegazione">Spiegazione guidata</h2>',
             '<p class="tenue">Lettura generata da regole fisse a partire dai dati del report: per ogni '
             "finding spiega cosa significa, come viene attaccato e cosa fare.</p>",
             f'<p class="verdetto {CLASSE_LIVELLO.get(verdetto["livello"], "info")}">'
             f'{_e(verdetto["testo"])}</p>']
    if lettura.get("punti_chiave"):
        parti.append("<ul>" + "".join(f"<li>{_e(p)}</li>" for p in lettura["punti_chiave"]) + "</ul>")

    priorita = lettura.get("priorita") or []
    if priorita:
        parti.append("<h3>Da dove cominciare</h3>")
        parti.append(f"<p>I {len(priorita)} finding con il rischio più alto, in ordine.</p>")
        parti += [_scheda(s, f"{n}. {_e(s.get('titolo'))}") for n, s in enumerate(priorita, 1)]

    altri = (lettura.get("spiegazioni") or [])[len(priorita):]
    if altri:
        parti.append("<h3>Tutti gli altri finding</h3>")
        parti += [_scheda(s, _e(s.get("titolo"))) for s in altri]

    if lettura.get("da_verificare"):
        parti.append("<h3>Da verificare a mano</h3>")
        parti.append("<p>Indizi senza un rischio valutato: la scansione non li ha potuti confermare.</p>")
        parti += [_scheda(s, _e(s.get("titolo")), con_perche=False) for s in lettura["da_verificare"]]

    parti.append("<h3>Cosa questa lettura non copre</h3>")
    parti.append("<ul>" + "".join(f"<li>{_e(lim)}</li>" for lim in lettura.get("limiti") or []) + "</ul>")
    return "".join(parti)


# --------------------------------------------------------------------------
# Documento
# --------------------------------------------------------------------------

def render(model, lettura=None):
    """Restituisce il report HTML web come stringa. lettura: il risultato di
    interprete_web.interpreta_web(model); se c'è, aggiunge la spiegazione guidata."""
    meta = model.get("meta") or {}
    sezioni = [_intestazione(meta)]
    if lettura is not None:
        sezioni.append('<p class="nota">Questo report contiene anche la '
                       '<a href="#spiegazione">spiegazione guidata</a> dei risultati.</p>')
    sezioni += [_ricognizione(model), _tabella_rischi(model.get("findings") or []), _portata(model)]
    if lettura is not None:
        sezioni.append(_spiegazione(lettura))
    sezioni.append(_note())
    titolo = f"VAPT web - {meta.get('target') or ''}".strip(" -")
    return ("<!doctype html>\n"
            '<html lang="it">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{_e(titolo)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n<main>\n"
            + "\n".join(sezioni)
            + "\n<footer>Generato da ApocalypseStriker. Report offline: nessuna risorsa esterna."
              "</footer>\n</main>\n</body>\n</html>\n")
