"""Sottopacchetto web di ApocalypseStriker: VAPT di applicazioni web.

recon.py      ricognizione passiva (header, cookie, TLS, tecnologie) - sola lettura
cve_nvd.py    CVE note delle tecnologie con versione, da NVD (interroga NVD, non il bersaglio)
web_risk.py   mappa le osservazioni su finding (OWASP + impatto x probabilita')
web_report.py pipeline del Vulnerability Assessment passivo e report Markdown
zap_scan.py   wrapper OWASP ZAP (penetration testing: fase rimandata, fuori dal flusso VA)
"""
