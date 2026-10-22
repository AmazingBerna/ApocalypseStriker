"""Modello dei dati del report, indipendente dal formato di uscita.

build_report_model() raccoglie tutto ciò che serve ai renderer (Markdown, JSON, CSV, HTML)
in un dizionario serializzabile in JSON così com'è: solo dict, list, str, int, bool e None.
"""
import hashlib
import re
from datetime import datetime

from .esposizione import applica as applica_esposizione
from .risk import assess_host_risks, overall_host_risk, sort_findings

# Campi di ogni finding, nell'ordine in cui compaiono nel modello
FINDING_FIELDS = ("id", "source", "host", "port", "protocol", "target", "item", "service",
                  "impact", "probability", "score", "level", "reason", "references",
                  "probability_basis", "probability_cve", "epss", "epss_percentile", "kev", "cvss",
                  "package", "network_vector", "exposure", "exposed_ports", "probability_bonus",
                  "confirmed_cves", "unconfirmed_cves",
                  # campi dei finding web (None per i finding host: Nmap, SSH, Lynis, Trivy)
                  "owasp", "url", "evidence")


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


def _lynis_number(findings, item):
    """Estrae un valore numerico dai finding informativi di Lynis (es. Hardening index)."""
    for f in findings:
        if f["source"] == "lynis" and f["item"] == item:
            match = re.search(r"\d+", f["reason"])
            if match:
                return int(match.group())
    return None


def build_report_model(
    hosts,
    target,
    vuln_scan,
    lynis_findings=None,
    lynis_meta=None,
    system_info=None,
    firewall=None,
    ssh_results=None,
    trivy_requested=False,
    trivy_summary=None,
    trivy_findings=None,
    tools_status=None,
    host_label="macchina locale",
    mode="locale",
    threat_intel=None,
    listening=None,
    trivy_inventory=None,
    udp_scan=None,
):
    """Costruisce il modello del report a partire dai risultati delle scansioni.
    threat_intel (KEV/EPSS) serve a valutare le CVE trovate da Nmap; None = valori fissi.
    listening (servizi in ascolto) e trivy_inventory (pacchetti controllati da Trivy) servono a
    esposizione.py per collegare porte e pacchetti; udp_scan è il numero di porte UDP
    scansionate (None = scansione UDP non eseguita)."""
    lynis_meta = lynis_meta or {}
    lynis_findings = lynis_findings or []
    ssh_results = ssh_results or {}
    trivy_findings = trivy_findings or []

    hosts = [{**h, "ports": [dict(p) for p in h["ports"]]} for h in hosts]
    host_findings = {h["ip"]: assess_host_risks(h, threat_intel) for h in hosts}
    # porte -> pacchetti, conferma delle CVE di Nmap, esposizione dei pacchetti di Trivy
    exposure = applica_esposizione(hosts, host_findings, trivy_findings,
                                   remota=mode.startswith("remota"), etichetta=host_label,
                                   listening=listening, inventory=trivy_inventory,
                                   intel=threat_intel)

    combined = []
    model_hosts = []
    for host in hosts:
        findings = sort_findings(host_findings[host["ip"]])
        score, level = overall_host_risk(findings)
        model_hosts.append({
            "ip": host["ip"],
            "hostname": host["hostname"],
            "ports": host["ports"],
            "overall_score": score,
            "overall_risk": level,
        })
        combined += [_normalize(f, host["ip"], host["ip"]) for f in findings]
    for endpoint, findings in ssh_results.items():
        ip, port = _split_endpoint(endpoint)
        combined += [_normalize(f, ip, endpoint, port) for f in findings]
    combined += [_normalize(f, host_label, host_label) for f in trivy_findings]
    combined += [_normalize(f, host_label, host_label) for f in lynis_findings]

    all_findings = sort_findings(combined)
    _assign_ids(all_findings)
    all_findings = [{k: f[k] for k in FINDING_FIELDS} for f in all_findings]

    return {
        "meta": {
            "target": str(target),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "analyzed_host": host_label,
            "mode": mode,
            "vuln_scan": bool(vuln_scan),
            "udp_scan": udp_scan,
            "trivy_requested": bool(trivy_requested),
            "tools": {name: (str(path) if path else None)
                      for name, path in (tools_status or {}).items()},
            "threat_intel": threat_intel.meta() if threat_intel is not None else None,
        },
        "system_info": system_info or "",
        # output di iptables: {command, output}, oppure None se non eseguito o non riuscito
        "firewall": dict(firewall) if firewall else None,
        "hosts": model_hosts,
        "exposure": exposure,
        "findings": all_findings,
        "summaries": {
            "trivy": dict(trivy_summary) if trivy_summary is not None else None,
            "lynis": {
                "enabled": bool(lynis_meta.get("enabled")),
                "report_file": str(lynis_meta["report_file"]) if lynis_meta.get("report_file") else None,
                "log_file": str(lynis_meta["log_file"]) if lynis_meta.get("log_file") else None,
                "hardening_index": _lynis_number(all_findings, "Hardening index"),
                "tests_performed": _lynis_number(all_findings, "Tests performed"),
            },
            "ssh_audit": {"endpoints": list(ssh_results)},
        },
    }
