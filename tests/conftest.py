"""Configurazione comune dei test: nessun accesso di rete.

Ogni tentativo di aprire una connessione fa fallire il test, così un test che per errore
contattasse un bersaglio, NVD o i feed KEV/EPSS se ne accorge subito.
"""
import socket

import pytest


class AccessoReteVietato(RuntimeError):
    pass


def _vietato(*_a, **_k):
    raise AccessoReteVietato("accesso di rete non consentito nei test")


@pytest.fixture(autouse=True)
def niente_rete(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _vietato)
    monkeypatch.setattr(socket.socket, "connect_ex", _vietato)
    monkeypatch.setattr(socket, "create_connection", _vietato)
    monkeypatch.setattr(socket, "getaddrinfo", _vietato)
