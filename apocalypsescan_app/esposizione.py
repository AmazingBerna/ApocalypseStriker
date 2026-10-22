"""Esposizione: quali pacchetti servono le porte aperte, e cosa cambia nel rischio.

Mette insieme Nmap (cosa si vede dalla rete), i servizi in ascolto (servizi_locali.py:
porta -> processo -> pacchetto) e Trivy (le CVE dei pacchetti), e corregge i finding:

1. a ogni porta della macchina analizzata associa i pacchetti che la servono: quello
   dell'eseguibile e quelli delle librerie che il processo ha caricato, letti dal sistema.
   Senza i servizi in ascolto (versioni vecchie del report, --skip-services, niente ss) li
   deduce dal prodotto rilevato da Nmap con le regole di SERVIZI;
2. conferma le CVE che Nmap deduce dal banner: una CVE che Trivy non trova nei pacchetti del
   servizio è, per la distribuzione, già corretta (backport) o non applicabile, e la
   probabilità del finding scende;
3. alza la probabilità delle CVE di Trivy nei pacchetti esposti in rete, se si sfruttano da
   rete (vettore CVSS AV:N): chiunque arrivi alla porta può raggiungerle.
"""
import re

from .config import (EXPOSURE_PROBABILITY_BONUS, NMAP_CVE, NMAP_CVE_MAX_PROBABILITY,
                     NMAP_CVE_UNCONFIRMED_PROBABILITY)
from .remote import is_local_address
from .risk import risk_level
from .threat_intel import assess_cves

# (servizio rilevato da Nmap, pacchetti che lo forniscono): espressioni regolari, la prima
# sul testo "servizio prodotto versione" in minuscolo, la seconda sul nome del pacchetto.
# È il ripiego quando i servizi in ascolto non sono stati letti dal sistema.
SERVIZI = [
    (r"openssh|^ssh\b", r"openssh(-server|-sftp-server)?"),
    (r"apache httpd", r"apache2(-bin|-data|-utils)?|httpd(-core|-tools|-filesystem)?"
                      r"|libapache2-mod-.+|mod_.+"),
    (r"tomcat", r"tomcat\d*(-.+)?"),
    (r"nginx", r"nginx(-.+)?|libnginx-mod-.+"),
    (r"lighttpd", r"lighttpd(-.+)?"),
    (r"mysql|mariadb", r"(mysql|mariadb)-(server|server-core.*|community-server|common)"),
    (r"postgresql", r"postgresql(-\d+|-server|-common)?"),
    (r"vsftpd", r"vsftpd"),
    (r"proftpd", r"proftpd(-.+)?"),
    (r"pure-ftpd", r"pure-ftpd(-.+)?"),
    (r"postfix", r"postfix(-.+)?"),
    (r"exim", r"exim4?(-.+)?"),
    (r"sendmail", r"sendmail(-.+)?"),
    (r"dovecot", r"dovecot(-.+)?"),
    (r"samba|smbd|microsoft-ds|netbios-ssn", r"samba(-.+)?|libsmbclient\d*|libwbclient\d*"),
    (r"isc bind|\bnamed\b", r"bind9?(-.+)?"),
    (r"dnsmasq", r"dnsmasq(-base)?"),
    (r"unbound", r"unbound|libunbound\d*"),
    (r"cups|^ipp\b", r"cups(-.+)?|libcups\d*"),
    (r"redis", r"redis(-server|-tools)?"),
    (r"mongodb", r"mongodb(-org)?(-server|-mongod)?"),
    (r"memcached", r"memcached"),
    (r"squid", r"squid(-.+)?"),
    (r"haproxy", r"haproxy"),
    (r"openldap|slapd|^ldap\b", r"slapd|openldap(-servers)?"),
    (r"rpcbind", r"rpcbind"),
    (r"^nfs\b|mountd|nlockmgr", r"nfs-kernel-server|nfs-utils|nfs-common"),
    (r"xrdp|ms-wbt-server", r"xrdp"),
    (r"vnc", r"tigervnc(-.+)?|tightvncserver|x11vnc|libvncserver\d*"),
    (r"avahi|mdns", r"avahi-daemon"),
    (r"^ntp\b|ntpd", r"ntp|ntpsec|chrony"),
    (r"snmp", r"snmpd|net-snmp"),
    (r"elasticsearch", r"elasticsearch"),
    (r"rabbitmq", r"rabbitmq-server"),
    (r"docker", r"docker(\.io|-ce)?|containerd(\.io)?"),
    (r"grafana", r"grafana(-server)?"),
    (r"node\.js|express", r"nodejs"),
    (r"werkzeug", r"werkzeug"),
    (r"gunicorn", r"gunicorn"),
    (r"python", r"python3(\.\d+)?(-minimal)?|libpython3.*"),
    (r"\bphp", r"php\d*(\.\d+)?(-fpm|-cli|-common)?|libapache2-mod-php.*"),
]

# I servizi cifrati con TLS usano la libreria del sistema: le sue CVE li riguardano tutti
PORTE_TLS = {443, 465, 563, 636, 853, 989, 990, 993, 995, 5061, 5986, 8443}
SERVIZIO_TLS = r"ssl|https|tls"
PACCHETTI_TLS = r"openssl|libssl.*|gnutls.*|libgnutls.*"


def nome_pacchetto(f):
    """Il pacchetto di un finding di Trivy: il campo package, oppure (report delle versioni
    precedenti) la prima parola dell'item. None per 'Altri N pacchetti (senza fix)'."""
    if f.get("package"):
        return f["package"]
    if re.match(r"Altri \d+ pacchetti", f["item"]):
        return None
    return f["item"].split(" ", 1)[0]


def descrizione_porta(p):
    return f"{p['port']}/{p['protocol']}"


def pacchetti_dedotti(p, nomi):
    """Ripiego senza i servizi in ascolto: i pacchetti, tra nomi, che forniscono il servizio
    rilevato da Nmap sulla porta p. Restituisce {nome: ruolo}, ruolo 'servizio' o 'libreria TLS'."""
    testo = " ".join(x for x in (p["service"], p["product"], p["version"]) if x).lower()
    trovati = {}
    regole = [r for s, r in SERVIZI if re.search(s, testo)]
    for nome in nomi:
        if any(re.fullmatch(r, nome) for r in regole):
            trovati[nome] = "servizio"
    if not regole and p["product"]:
        # servizio fuori tabella: il pacchetto con il nome del prodotto (Jetty -> jetty)
        parola = re.match(r"[a-z0-9]+", p["product"].lower())
        if parola and len(parola.group()) >= 3:
            for nome in nomi:
                if nome == parola.group() or nome.startswith(parola.group() + "-"):
                    trovati[nome] = "servizio"
    if p["port"] in PORTE_TLS or re.search(SERVIZIO_TLS, testo):
        for nome in nomi:
            if nome not in trovati and re.fullmatch(PACCHETTI_TLS, nome):
                trovati[nome] = "libreria TLS"
    return trovati


def host_analizzati(hosts, remota, etichetta):
    """Gli IP, tra gli host di Nmap, della macchina su cui girano i controlli interni.

    In remoto è il target della connessione SSH ("IP (via SSH)"); in locale è questa
    macchina, riconosciuta dai suoi indirizzi."""
    if remota:
        nome = re.sub(r" \(via SSH\)$", "", etichetta or "")
        trovati = {h["ip"] for h in hosts if nome in (h["ip"], h.get("hostname"))}
        if not trovati and len(hosts) == 1:   # target dato per nome, Nmap riporta l'IP
            trovati = {hosts[0]["ip"]}
        return trovati
    return {h["ip"] for h in hosts if h["ip"] and is_local_address(h["ip"])}


def _pacchetti_porta(p, servizio, nomi_noti):
    """I pacchetti della porta p: dal sistema (servizio in ascolto) o dedotti da Nmap."""
    if servizio and servizio["package"]:
        pacchetti = [{"name": servizio["package"], "version": servizio["package_version"],
                      "role": "servizio", "source": "sistema"}]
        pacchetti += [{"name": lib["package"], "version": lib["version"],
                       "role": "libreria", "source": "sistema"} for lib in servizio["libraries"]]
        return pacchetti
    return [{"name": nome, "version": None, "role": ruolo, "source": "regole"}
            for nome, ruolo in sorted(pacchetti_dedotti(p, nomi_noti).items())]


def _ricalcola(f, probability):
    f["probability"] = probability
    f["score"] = f["impact"] * probability
    f["level"] = risk_level(f["score"])


def _conferma_nmap_vuln(f, pacchetti, inventory, intel):
    """Confronta le CVE di nmap-vuln con quelle che Trivy ha trovato nei pacchetti della
    porta. Si può fare solo se Trivy ha controllato almeno uno di quei pacchetti."""
    controllati = [x["name"] for x in pacchetti if x["name"] in inventory["packages"]]
    if not controllati:
        return
    trovate = set().union(*(inventory["cves"].get(n, set()) for n in controllati))
    confermate = [c for c in f["references"] if c in trovate]
    f["confirmed_cves"] = confermate
    f["unconfirmed_cves"] = [c for c in f["references"] if c not in trovate]
    elenco = ", ".join(controllati[:3]) + (" e altri" if len(controllati) > 3 else "")
    if confermate:
        probability, fields = assess_cves(intel, confermate, NMAP_CVE[1],
                                          max_probability=NMAP_CVE_MAX_PROBABILITY)
        f.update(fields)
        f["reason"] += (f" Trivy ne conferma {len(confermate)} su {len(f['references'])} "
                        f"nei pacchetti installati ({elenco}).")
    else:
        probability = NMAP_CVE_UNCONFIRMED_PROBABILITY
        f.update(probability_basis="non-confermata", probability_cve=None,
                 epss=None, epss_percentile=None, kev=None)
        f["reason"] += (f" Trivy non ne trova nessuna nei pacchetti installati ({elenco}): "
                        "probabilmente sono già corrette dalla distribuzione.")
    _ricalcola(f, probability)


def _esponi_trivy(f, porte_rete, porte_locali):
    nome = nome_pacchetto(f)
    if nome in porte_rete:
        f["exposure"] = "rete"
        f["exposed_ports"] = porte_rete[nome]
        # il bonus vale se la CVE peggiore non è già certa (KEV) e se almeno una CVE si
        # sfrutta da rete: una CVE solo locale (AV:L) non diventa più probabile
        if (f.get("probability_basis") != "kev" and f.get("network_vector") is not False
                and f["probability"] < 5):
            nuova = min(5, f["probability"] + EXPOSURE_PROBABILITY_BONUS)
            f["probability_bonus"] = nuova - f["probability"]
            _ricalcola(f, nuova)
    elif nome in porte_locali:
        f["exposure"] = "locale"
        f["exposed_ports"] = porte_locali[nome]


def applica(hosts, host_findings, trivy_findings, remota, etichetta,
            listening=None, inventory=None, intel=None):
    """Annota porte e finding (li modifica sul posto) e restituisce il riepilogo
    dell'esposizione per il modello del report.

    host_findings: {ip: finding di Nmap dell'host}; listening: servizi_locali.parse_listening;
    inventory: trivy_scan.trivy_inventory."""
    analizzati = host_analizzati(hosts, remota, etichetta)
    servizi = {(s["protocol"], s["port"]): s for s in (listening or {}).get("services", [])}
    if inventory:
        nomi_noti = list(inventory["packages"])
    else:
        nomi_noti = sorted({n for f in trivy_findings if (n := nome_pacchetto(f))})

    porte_rete, viste = {}, set()
    for h in hosts:
        if h["ip"] not in analizzati:
            continue
        for p in h["ports"]:
            servizio = servizi.get((p["protocol"], p["port"]))
            viste.add((p["protocol"], p["port"]))
            p["packages"] = _pacchetti_porta(p, servizio, nomi_noti)
            p["process"] = ", ".join(servizio["processes"]) if servizio else None
            p["restart_needed"] = bool(servizio and servizio["restart_needed"])
            for x in p["packages"]:
                porte_rete.setdefault(x["name"], []).append(descrizione_porta(p))
            if inventory:
                for f in host_findings.get(h["ip"], []):
                    if (f["source"] == "nmap-vuln" and f["port"] == p["port"]
                            and f.get("protocol", "tcp") == p["protocol"]):
                        _conferma_nmap_vuln(f, p["packages"], inventory, intel)

    # servizi in ascolto che Nmap non ha visto: solo su localhost, filtrati o non scansionati
    porte_locali, in_ascolto = {}, []
    for (protocollo, porta), s in servizi.items():
        if (protocollo, porta) in viste:
            visibilita = "rete"
        elif s["loopback_only"]:
            visibilita = "localhost"
        else:
            visibilita = "non vista da Nmap"
        if visibilita != "rete":
            for nome in [s["package"], *(lib["package"] for lib in s["libraries"])]:
                if nome:
                    porte_locali.setdefault(nome, []).append(f"{porta}/{protocollo}")
        in_ascolto.append({**s, "visibility": visibilita})

    if analizzati:
        for f in trivy_findings:
            _esponi_trivy(f, porte_rete, porte_locali)

    return {
        "analyzed_ips": sorted(analizzati),
        "listening_read": listening is not None,
        "package_manager": (listening or {}).get("manager"),
        "listening": in_ascolto,
        "restart_needed": sorted({p for s in in_ascolto if s["restart_needed"]
                                  for p in s["processes"]}),
    }
