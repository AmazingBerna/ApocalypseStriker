"""cli.py - Punto di ingresso del comando `apocalypse` (ApocalypseStriker).

  apocalypse attack               apre il menù interattivo (apocalypsescan_app.menu_web)
  apocalypse attack <url>         esegue il Vulnerability Assessment web su <url>
  apocalypse attack <url> --help  tutte le opzioni della scansione web

`apocalypse` è il comando della serie Apocalypse (la versione precedente si lanciava con
`apocalypse scan`); questa terza versione aggiunge il sottocomando `attack`. Registrato
come console script in pyproject.toml, sezione [project.scripts]: `pip install -e .` crea
nel venv un comando `apocalypse` che chiama questa funzione main().
"""
import sys

USO = """\
ApocalypseStriker - VAPT di applicazioni web

Uso:
  apocalypse attack               apre il menù interattivo (guida e scansione guidata)
  apocalypse attack <url>         esegue il Vulnerability Assessment passivo su <url>
  apocalypse attack <url> --help  tutte le opzioni della scansione web

Esempi:
  apocalypse attack
  apocalypse attack https://badssl.com
  apocalypse attack https://esempio.it --env produzione --format md,json,csv
"""


def main(argv=None):
    """Smista il comando: `attack` senza URL apre il menù, con un URL lancia la scansione.

    `apocalypse attack <url> [opzioni]` passa <url> e le opzioni alla scansione già
    esistente (web_report.main): la logica di scansione non viene riscritta."""
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "attack":
        rest = argv[1:]
        if not rest:
            from apocalypsescan_app.menu_web import menu_principale
            return menu_principale()
        from apocalypsescan_app.web.web_report import main as web_main
        return web_main(rest)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USO)
        return 0

    print(f"Sottocomando sconosciuto: {argv[0]}\n", file=sys.stderr)
    print(USO, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
