"""Contenuti condivisi dai renderer leggibili (Markdown e HTML).

Qui stanno i dati, non la formattazione: ogni renderer li impagina a modo suo.
Nei testi, `x` indica un nome da mostrare come codice.
"""
from ..config import (
    RISK_THRESHOLDS,
    RISKY_SERVICES, LOW_RISK_DEFAULT, RISKY_UDP_SERVICES, LOW_RISK_UDP_DEFAULT,
    UNKNOWN_SERVICE, NMAP_CVE, NMAP_CVE_UNCONFIRMED_PROBABILITY, EXPOSURE_PROBABILITY_BONUS,
    SSH_NOTE_RISK, SSH_CVE, SSH_RECOMMENDATION,
    TRIVY_IMPACT, TRIVY_PROBABILITY_FIX, TRIVY_PROBABILITY_NO_FIX,
    LYNIS_WARNING, LYNIS_SUGGESTION,
    KEV_PROBABILITY, EPSS_PROBABILITY, EPSS_MIN_PROBABILITY, CVSS_PROBABILITY,
    NMAP_CVE_MAX_PROBABILITY, TRIVY_PROMOTED_IMPACT, TRIVY_PROMOTE_MIN_EPSS,
)

SCORED_LEVELS = ("Critico", "Alto", "Medio", "Basso")


def percent(value):
    """0.94321 -> '94,32%'; i valori che arrotondati darebbero 100% restano '>99,99%'."""
    if value >= 0.99995:
        return ">99,99%"
    return f"{value * 100:.2f}%".replace(".", ",")


def thresholds_text():
    """'16-25 = Critico, 10-15 = Alto, ...'"""
    parts = []
    upper = 25
    for minimum, level in RISK_THRESHOLDS:
        parts.append(f"{minimum}-{upper} = {level}")
        upper = minimum - 1
    return ", ".join(parts)


def by_source(findings, sources, target=None):
    """Finding di certe fonti (e di un certo target), nell'ordine di rischio del modello."""
    return [f for f in findings
            if f["source"] in sources and (target is None or f["target"] == target)]


def criteria_rows():
    """Criteri di assegnazione per fonte: (fonte, caso, impatto, probabilità, criterio)."""
    rows = []
    for port, (name, i, p, _) in sorted({**RISKY_SERVICES, **LOW_RISK_DEFAULT}.items()):
        rows.append(("nmap", f"{port} {name}", i, p, "Database euristico dei servizi esposti"))
    for port, (name, i, p, _) in sorted({**RISKY_UDP_SERVICES, **LOW_RISK_UDP_DEFAULT}.items()):
        rows.append(("nmap", f"{port}/udp {name}", i, p, "Database euristico dei servizi UDP (--udp)"))
    rows.append(("nmap", "Servizio non catalogato", UNKNOWN_SERVICE[0], UNKNOWN_SERVICE[1],
                 "Superficie esposta di natura non nota"))
    rows.append(("nmap-vuln", "CVE da script NSE", NMAP_CVE[0], NMAP_CVE[1],
                 "Corrispondenza solo sulla versione del banner, da confermare"))
    rows.append(("nmap-vuln", "Nessuna CVE confermata da Trivy", NMAP_CVE[0], NMAP_CVE_UNCONFIRMED_PROBABILITY,
                 "Il pacchetto del servizio non ha queste CVE: già corrette dalla distribuzione"))
    rows.append(("ssh-audit", "Algoritmo `fail`", SSH_NOTE_RISK["fail"][0], SSH_NOTE_RISK["fail"][1],
                 "Crittografia debole, sfruttabile solo con posizione privilegiata in rete"))
    rows.append(("ssh-audit", "Algoritmo `warn`", SSH_NOTE_RISK["warn"][0], SSH_NOTE_RISK["warn"][1],
                 "Algoritmo sconsigliato ma non rotto"))
    rows.append(("ssh-audit", "CVE della versione", SSH_CVE[0], SSH_CVE[1],
                 "Servizio esposto con vulnerabilità nota"))
    rows.append(("ssh-audit", "Raccomandazione critica", SSH_RECOMMENDATION[0], SSH_RECOMMENDATION[1],
                 "Configurazione da correggere"))
    for sev, i in TRIVY_IMPACT.items():
        rows.append(("trivy", f"{sev} con fix", i, TRIVY_PROBABILITY_FIX,
                     "Impatto dalla gravità; vulnerabilità pubblica e documentata"))
        rows.append(("trivy", f"{sev} senza fix", i, TRIVY_PROBABILITY_NO_FIX,
                     "Spesso non sfruttabile nella configurazione di default della distribuzione"))
    rows.append(("trivy", "Pacchetto di una porta aperta", "come sopra", f"+{EXPOSURE_PROBABILITY_BONUS}",
                 "CVE raggiungibili dalla rete (solo se almeno una ha vettore AV:N, senza superare 5)"))
    rows.append(("lynis", "Warning", LYNIS_WARNING[0], LYNIS_WARNING[1], "Problema di configurazione rilevato"))
    rows.append(("lynis", "Suggestion", LYNIS_SUGGESTION[0], LYNIS_SUGGESTION[1], "Miglioramento di hardening"))
    return rows


def threat_intel_rows():
    """Probabilità delle CVE dai dati sulle minacce: (condizione, probabilità, fonte)."""
    rows = [("CVE nel catalogo KEV (sfruttata attivamente)", KEV_PROBABILITY, "CISA KEV")]
    for minimum, probability in EPSS_PROBABILITY:
        rows.append((f"EPSS ≥ {percent(minimum)}", probability, "FIRST EPSS"))
    rows.append((f"EPSS < {percent(EPSS_PROBABILITY[-1][0])}", EPSS_MIN_PROBABILITY, "FIRST EPSS"))
    rows.append(("Senza EPSS, vettore CVSS AV:N/PR:N/UI:N", CVSS_PROBABILITY["network_unauth"], "CVSS"))
    rows.append(("Senza EPSS, vettore CVSS AV:N con privilegi o interazione", CVSS_PROBABILITY["network"], "CVSS"))
    rows.append(("Senza EPSS, vettore CVSS AV:A o AV:L", CVSS_PROBABILITY["adjacent_local"], "CVSS"))
    rows.append(("Senza EPSS, vettore CVSS AV:P", CVSS_PROBABILITY["physical"], "CVSS"))
    rows.append(("Nessun dato", "valore della tabella precedente", "euristica"))
    return rows


def threat_intel_note(kev_tag="[KEV]"):
    """Le avvertenze sotto la tabella KEV/EPSS; kev_tag è il marcatore KEV già formattato."""
    return (f"Per nmap-vuln la probabilità non supera {NMAP_CVE_MAX_PROBABILITY}, perché le CVE sono "
            "dedotte dal solo banner di versione. Trivy elenca anche le CVE "
            f"{' e '.join(TRIVY_PROMOTED_IMPACT)} presenti nel KEV o con EPSS ≥ "
            f"{percent(TRIVY_PROMOTE_MIN_EPSS)}, con impatto "
            f"{' e '.join(str(i) for i in TRIVY_PROMOTED_IMPACT.values())}. Nel dettaglio dei "
            f"finding, {kev_tag} e [EPSS] riportano i valori della CVE peggiore.")


def threat_intel_data(intel_meta):
    """'Dati usati: catalogo KEV versione ... (n CVE), EPSS del ... (modello ...).'"""
    kev, epss = intel_meta["kev"], intel_meta["epss"]
    return (f"Dati usati: catalogo KEV versione {kev['catalog_version']} "
            f"({kev['count']} CVE), EPSS del {(epss['score_date'] or '?')[:10]} "
            f"(modello {epss['model_version']}).")


# --------------------------------------------------------------------------
# Porte, pacchetti ed esposizione (esposizione.py)
# --------------------------------------------------------------------------

VISIBILITA = {
    "rete": "aperta verso la rete (vista da Nmap)",
    "localhost": "solo localhost",
    "non vista da Nmap": "in ascolto ma non vista da Nmap (firewall o porta non scansionata)",
}


def port_label(f):
    """'22' per il TCP, '53/udp' per l'UDP: la colonna Porta delle tabelle."""
    if f.get("port") is None:
        return None
    return f"{f['port']}/udp" if f.get("protocol") == "udp" else str(f["port"])


def exposure_tags(f):
    """Etichette sull'esposizione e sulla conferma delle CVE: testo semplice, i renderer
    le impaginano. Vuoto per i finding dei report delle versioni precedenti."""
    tags = []
    if f.get("exposure") == "rete":
        bonus = f" (probabilità +{f['probability_bonus']})" if f.get("probability_bonus") else ""
        tags.append(f"esposto in rete su {', '.join(f['exposed_ports'])}{bonus}")
    elif f.get("exposure") == "locale":
        tags.append(f"in ascolto non visibile dalla rete su {', '.join(f['exposed_ports'])}")
    if f.get("confirmed_cves") is not None:
        n, tot = len(f["confirmed_cves"]), len(f["references"])
        tags.append(f"confermate da Trivy: {n} su {tot}" if n else "nessuna confermata da Trivy")
    return tags


def _pacchetto(x):
    return f"{x['name']} {x['version']}" if x.get("version") else x["name"]


def port_packages_text(host, f):
    """'sshd · openssh-server 1:9.6p1 + 14 librerie', per la riga Nmap della porta.
    None se la porta non è della macchina analizzata o non ha pacchetti collegati."""
    p = next((p for p in host["ports"] if p["port"] == f.get("port")
              and p["protocol"] == (f.get("protocol") or "tcp")), None)
    if not p or not p.get("packages"):
        return None
    servizio = [x for x in p["packages"] if x["role"] == "servizio"]
    altri = len(p["packages"]) - len(servizio)
    testo = ", ".join(_pacchetto(x) for x in servizio) or "pacchetto non identificato"
    if altri:
        testo += f" + {altri} {'libreria' if altri == 1 else 'librerie'}"
    if p["packages"][0]["source"] == "regole":
        testo += " (dedotto dal prodotto rilevato da Nmap)"
    if p.get("process"):
        testo = f"{p['process']} · {testo}"
    if p.get("restart_needed"):
        testo += " · da riavviare: in memoria gira il codice prima dell'aggiornamento"
    return testo


def listening_rows(exposure):
    """Righe della tabella dei servizi in ascolto:
    (porta, processi, pacchetto, librerie, visibilità, da riavviare)."""
    rows = []
    for s in (exposure or {}).get("listening", []):
        pacchetto = (f"{s['package']} {s['package_version'] or ''}".strip()
                     if s["package"] else "non di un pacchetto")
        rows.append((f"{s['port']}/{s['protocol']}", ", ".join(s["processes"]) or "?",
                     pacchetto, len(s["libraries"]), VISIBILITA.get(s["visibility"], s["visibility"]),
                     s["restart_needed"]))
    return rows
