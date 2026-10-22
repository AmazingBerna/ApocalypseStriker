from .config import (
    RISKY_SERVICES, LOW_RISK_DEFAULT, RISKY_UDP_SERVICES, LOW_RISK_UDP_DEFAULT,
    UNKNOWN_SERVICE, NMAP_CVE, NMAP_CVE_MAX_PROBABILITY, RISK_THRESHOLDS,
)
from .threat_intel import assess_cves


def risk_level(score):
    """Converte il punteggio impatto x probabilità (1-25) in un livello."""
    for minimum, level in RISK_THRESHOLDS:
        if score >= minimum:
            return level
    return "Informativo"


def make_finding(source, item, impact, probability, reason, **extra):
    """Crea un finding con rischio = impatto x probabilità."""
    score = impact * probability
    return {
        "source": source,
        "item": item,
        "impact": impact,
        "probability": probability,
        "score": score,
        "level": risk_level(score),
        "reason": reason,
        **extra,
    }


def info_finding(source, item, reason, **extra):
    """Finding puramente informativo: non entra nel calcolo del rischio."""
    return {
        "source": source,
        "item": item,
        "impact": None,
        "probability": None,
        "score": 0,
        "level": "Informativo",
        "reason": reason,
        **extra,
    }


def service_rule(port, protocol="tcp"):
    """(servizio, impatto, probabilità, motivazione) della porta, dalle tabelle del suo
    protocollo (il rischio della 514/udp, syslog, non è quello della 514/tcp, rsh); None se
    la porta non è catalogata."""
    tables = ((RISKY_UDP_SERVICES, LOW_RISK_UDP_DEFAULT) if protocol == "udp"
              else (RISKY_SERVICES, LOW_RISK_DEFAULT))
    for table in tables:
        if port in table:
            return table[port]
    return None


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f["score"], f["impact"] or 0), reverse=True)


def assess_host_risks(host, intel=None):
    """Finding delle porte aperte e delle CVE trovate da Nmap. Con intel (dati KEV/EPSS)
    la probabilità delle CVE viene dai dati sulle minacce invece che dal valore fisso."""
    findings = []

    for p in host["ports"]:
        port = p["port"]
        service_desc = p["service"]
        if p["product"]:
            service_desc += f" ({' '.join(x for x in (p['product'], p['version']) if x)})"
        protocol = p["protocol"]
        item = f"{port}/{protocol} {service_desc}"

        rule = service_rule(port, protocol)
        if rule:
            _, impact, probability, reason = rule
        else:
            impact, probability = UNKNOWN_SERVICE
            reason = ("Servizio non presente nel database euristico interno: verificare "
                      "manualmente necessità ed esposizione.")

        findings.append(make_finding("nmap", item, impact, probability, reason,
                                     port=port, protocol=protocol, service=service_desc))

    cves_by_port = {}
    for vn in host["vuln_notes"]:
        key = (vn["port"], vn.get("protocol", "tcp"))
        cves_by_port.setdefault(key, []).append(vn["cve"])

    for (port, protocol), cves in cves_by_port.items():
        cves = sorted(cves)
        shown = ", ".join(cves[:5])
        if len(cves) > 5:
            shown += f" e altre {len(cves) - 5}"
        impact, default_probability = NMAP_CVE
        probability, intel_fields = assess_cves(intel, cves, default_probability,
                                                max_probability=NMAP_CVE_MAX_PROBABILITY)
        label = f"{port}/udp" if protocol == "udp" else str(port)
        findings.append(make_finding(
            "nmap-vuln", f"{label} - {len(cves)} CVE", impact, probability,
            f"{shown}. Identificate confrontando il banner di versione: molte possono "
            "non essere applicabili, verificare su nvd.nist.gov",
            port=port, protocol=protocol, service=f"{len(cves)} CVE da script Nmap", references=cves,
            **intel_fields,
        ))

    return sort_findings(findings)


def overall_host_risk(findings):
    """Restituisce (punteggio, livello) del finding peggiore; senza finding valutati
    l'host è solo informativo (nessuna porta aperta)."""
    scored = [f for f in findings if f["score"]]
    if not scored:
        return 0, "Informativo"
    worst = max(scored, key=lambda f: f["score"])
    return worst["score"], worst["level"]
