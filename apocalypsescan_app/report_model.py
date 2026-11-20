"""Schema comune dei finding, indipendente dal formato di uscita.

_normalize() porta ogni finding (web passivo, penetration testing, analisi interna) allo
stesso schema FINDING_FIELDS; _assign_ids() gli dà un id stabile. Il modello è
serializzabile in JSON così com'è: solo dict, list, str, int, bool e None.

Il vecchio build_report_model() del report "host" (Nmap, Trivy, Lynis) è archiviato in
docs/archivio/report_host/report_model_host.py.
"""
import hashlib
import re

# Campi di ogni finding, nell'ordine in cui compaiono nel modello
FINDING_FIELDS = ("id", "source", "host", "port", "protocol", "target", "item", "service",
                  "impact", "probability", "score", "level", "reason", "references",
                  "probability_basis", "probability_cve", "epss", "epss_percentile", "kev", "cvss",
                  "package", "network_vector", "exposure", "exposed_ports", "probability_bonus",
                  "confirmed_cves", "unconfirmed_cves",
                  # campi dei finding web (None per i finding host: Nmap, SSH, Lynis, Trivy)
                  "owasp", "url", "evidence",
                  # fonte: "esterno" (recon/PT web) o "interno" (inspect); elemento: cosa è
                  # interessato (porta, utente del DB, file:riga...). Aggiunti in fondo: chi
                  # legge già il JSON trova tutti i campi di prima
                  "fonte", "elemento",
                  # esito della verifica di PT (web/esito_pt.py) e la sua spiegazione breve
                  "esito_pt", "esito_pt_nota")


def _slug(text):
    """Parte di id leggibile: minuscole, cifre, punti e trattini."""
    return re.sub(r"[^a-z0-9.]+", "-", str(text).lower()).strip("-") or "x"


def _split_endpoint(endpoint):
    """'IP:porta' -> (IP, porta). Usa l'ultimo ':' per non spezzare gli indirizzi IPv6."""
    host, sep, port = str(endpoint).rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return str(endpoint), None


def _normalize(f, host, target, port=None):
    """Porta un finding allo schema comune del modello (id escluso)."""
    return {
        "source": f["source"],
        "host": host,
        "port": f.get("port", port),
        "protocol": f.get("protocol", "tcp" if f.get("port", port) is not None else None),
        "target": target,
        "item": f["item"],
        "service": f.get("service"),
        "impact": f["impact"],
        "probability": f["probability"],
        "score": f["score"],
        "level": f["level"],
        "reason": f["reason"],
        "references": list(f.get("references", [])),
        # da dove viene la probabilità: kev, epss, cvss o euristica (valori fissi di config.py)
        "probability_basis": f.get("probability_basis", "euristica"),
        "probability_cve": f.get("probability_cve"),
        "epss": f.get("epss"),
        "epss_percentile": f.get("epss_percentile"),
        "kev": f.get("kev"),
        "cvss": f.get("cvss"),
        # pacchetto di Trivy e vettore d'attacco delle sue CVE (True = almeno una AV:N)
        "package": f.get("package"),
        "network_vector": f.get("network_vector"),
        # esposizione.py: "rete" (pacchetto di una porta aperta), "locale" (servizio non
        # visibile dalla rete) o None; il bonus di probabilità applicato per l'esposizione
        "exposure": f.get("exposure"),
        "exposed_ports": f.get("exposed_ports"),
        "probability_bonus": f.get("probability_bonus"),
        # nmap-vuln: le CVE confermate o no da Trivy (None = confronto non possibile)
        "confirmed_cves": f.get("confirmed_cves"),
        "unconfirmed_cves": f.get("unconfirmed_cves"),
        # finding web (web_risk.py): categoria OWASP, URL/endpoint, evidenza sintetica
        "owasp": f.get("owasp"),
        "url": f.get("url"),
        "evidence": f.get("evidence"),
        "fonte": f.get("fonte") or "esterno",
        "elemento": f.get("elemento"),
        "esito_pt": f.get("esito_pt"),
        "esito_pt_nota": f.get("esito_pt_nota"),
        "key": f.get("key"),   # solo per l'id, non entra nel modello
    }


def _assign_ids(findings):
    """Assegna a ogni finding un id stabile e univoco.

    L'id base è leggibile (fonte, host, porta, voce). Come voce si usa la "key" fornita
    dal parser quando l'item contiene conteggi che cambiano da una scansione all'altra.
    Se due finding condividono l'id base, si aggiunge un hash del contenuto, che non
    dipende dall'ordine di scansione."""
    used = set()
    for f in findings:
        parts = [_slug(f["source"]), _slug(f["host"])]
        if f["port"] is not None:
            parts.append(_slug(f["port"]))
            if f["protocol"] == "udp":    # le porte TCP tengono l'id delle versioni precedenti
                parts.append("udp")
        if f["source"] not in ("nmap", "nmap-vuln"):   # qui host e porta bastano a identificare la voce
            parts.append(_slug(f["key"] or f["item"])[:60].rstrip("-"))
        base = "-".join(parts)

        candidate = base
        if candidate in used:
            digest = hashlib.sha1(f"{f['item']}|{f['reason']}".encode("utf-8")).hexdigest()[:8]
            candidate = f"{base}-{digest}"
        n = 2
        while candidate in used:     # finding identici: ultimo ripiego, un contatore
            candidate = f"{base}-{n}"
            n += 1
        used.add(candidate)
        f["id"] = candidate
