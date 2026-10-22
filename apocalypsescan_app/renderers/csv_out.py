"""Renderer CSV: la sola lista dei finding, una riga per finding."""
import csv
import io

COLUMNS = ("id", "source", "host", "port", "protocol", "item", "level", "reason", "references",
           "impact", "probability", "score",
           "probability_basis", "probability_cve", "epss", "epss_percentile", "kev", "cvss",
           "package", "exposure", "exposed_ports", "probability_bonus",
           "confirmed_cves", "unconfirmed_cves")


def render(model):
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in model["findings"]:
        row = {**f, "references": ";".join(f["references"])}
        for lista in ("exposed_ports", "confirmed_cves", "unconfirmed_cves"):
            if f.get(lista) is not None:
                row[lista] = ";".join(f[lista])
        if f["kev"] is not None:
            row["kev"] = "true" if f["kev"] else "false"
        writer.writerow(row.get(c) for c in COLUMNS)   # None diventa una cella vuota
    return buffer.getvalue()
