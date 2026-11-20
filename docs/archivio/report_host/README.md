# Archivio: report "host" della versione precedente

Questi file vengono da **ApocalypseScan**, la versione della serie che analizzava una macchina
Linux con Nmap, ssh-audit, Trivy e Lynis. ApocalypseStriker non li usa: sono stati tolti dal
pacchetto `apocalypsescan_app/` per non lasciare codice morto e riferimenti a moduli che non
esistono in questo repo (`servizi_locali.parse_listening` nella vecchia forma,
`trivy_scan.trivy_inventory`).

| File | Da dove viene | Cosa faceva |
|---|---|---|
| `esposizione.py` | `apocalypsescan_app/esposizione.py` | collegava porte (Nmap), servizi in ascolto e pacchetti (Trivy), e correggeva la probabilità delle CVE |
| `report_model_host.py` | `report_model.py` | `build_report_model()`: il modello del report host |
| `risk_host.py` | `risk.py` | `assess_host_risks()`, `service_rule()`, `overall_host_risk()`: rischio delle porte di Nmap |
| `common_host.py` | `renderers/common.py` | testi e tabelle del report host (criteri, KEV/EPSS, esposizione) |

Sono conservati **solo come riferimento**: non sono importabili così come sono (usano import
relativi del pacchetto originale). I parametri che usavano (`RISKY_SERVICES`, `NMAP_CVE`,
`TRIVY_*`, `LYNIS_*`, …) sono rimasti in `apocalypsescan_app/config.py`.

L'analisi interna di Striker (`apocalypse inspect`) **non** dipende da questi file: ha il suo
raccoglitore dei servizi in ascolto, `apocalypsescan_app/servizi_locali.py`.
