"""ARCHIVIO - codice del report "host" della versione precedente (ApocalypseScan:
Nmap, ssh-audit, Trivy, Lynis), tolto da report_model.py perché ApocalypseStriker non lo usa.
Conservato solo come riferimento: NON è importabile così com'è (import relativi del
pacchetto originale). Vedi README.md in questa cartella."""



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
