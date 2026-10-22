"""Renderer del report: ognuno espone render(model) -> str.

ApocalypseStriker (solo web) usa i renderer del modello web: markdown_web (report
leggibile), json_out (il modello completo) e csv_out (i finding in tabella). I
renderer host (markdown, html_out) e la tabella RENDERERS host sono stati rimossi
con la pulizia web-only. Il formato/percorso del report web lo gestisce
web.web_report (RENDERERS_WEB)."""
from . import csv_out, json_out, markdown_web
