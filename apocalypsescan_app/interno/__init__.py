"""Analisi INTERNA della macchina che ospita l'applicazione (apocalypse inspect).

Entra nella macchina con credenziali autorizzate (SSH a chiave, oppure in locale) e la
analizza in SOLA LETTURA: processi e servizi, database, codice sorgente, web server.
Ogni comando passa da comandi.EsecutoreSolaLettura, che lo confronta con l'elenco ammesso.
"""
