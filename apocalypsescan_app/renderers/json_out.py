"""Renderer JSON: il modello del report così com'è.

Il modulo non si chiama json.py per non nascondere la libreria standard."""
import json


def render(model):
    return json.dumps(model, indent=2, ensure_ascii=False)
