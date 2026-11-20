"""Renderer CSV: la sola lista dei finding, una riga per finding."""
import csv
import io

from .common import elemento
from ..web.esito_pt import esito_di, fonte_di

COLUMNS = ("id", "source", "host", "port", "protocol", "item", "level", "reason", "references",
           "impact", "probability", "score",
           "probability_basis", "probability_cve", "epss", "epss_percentile", "kev", "cvss",
           "package", "exposure", "exposed_ports", "probability_bonus",
           "confirmed_cves", "unconfirmed_cves",
           # colonne aggiunte in fondo: chi legge il CSV per posizione trova le stesse di prima
           "owasp", "url", "evidence", "fonte", "elemento", "esito_pt", "esito_pt_nota")


def render(model):
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in model["findings"]:
        row = {**f, "references": ";".join(f.get("references") or [])}
        for lista in ("exposed_ports", "confirmed_cves", "unconfirmed_cves"):
            if f.get(lista) is not None:
                row[lista] = ";".join(f[lista])
        row["fonte"] = fonte_di(f)
        row["esito_pt"] = esito_di(f)
        row["elemento"] = elemento(f)
        if f.get("kev") is not None:
            row["kev"] = "true" if f["kev"] else "false"
        writer.writerow(row.get(c) for c in COLUMNS)   # None diventa una cella vuota
    return buffer.getvalue()
