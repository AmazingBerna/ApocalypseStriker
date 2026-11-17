# WebPenetrationTester

> ℹ️ **Nota.** Questo è il **primo prototipo** standalone del penetration testing. La versione
> integrata e attiva è ora il modulo [`apocalypsescan_app/web/pentest.py`](../apocalypsescan_app/web/pentest.py),
> che si lancia con `apocalypse attack <url> --pentest`: scopre i punti di input (crawler + form),
> invia davvero i payload (confronto differenziale rispetto a una risposta di base) e integra i
> finding nel report VAPT con categoria OWASP e scoring Impatto × Probabilità. Questo script resta
> come riferimento/esperimento; per la battle usa il modulo integrato.

Uno strumento semplice ma potente per il testing di penetrazione delle applicazioni web. Questo tool permette di effettuare controlli automatici di sicurezza su applicazioni web per identificare vulnerabilità comuni.

## 📋 Descrizione

WebPenetrationTester è uno strumento di test di sicurezza che effettua controlli automatici per individuare vulnerabilità comuni nelle applicazioni web. È pensato per essere utilizzato in modo legittimo e autorizzato su applicazioni che ti appartengono o per cui hai il permesso esplicito.

## ⚠️ Avviso Importante

🔐 **Utilizzo Legittimo Richiesto**: Questo strumento deve essere utilizzato solo su applicazioni per cui hai il permesso esplicito. L'utilizzo non autorizzato di strumenti di penetrazione su sistemi altrui è illegale.

## ✨ Funzionalità

- **SQL Injection Detection**: Rileva potenziali vulnerabilità SQL Injection
- **XSS (Cross-Site Scripting)**: Verifica vulnerabilità XSS
- **Directory Traversal**: Controlla vulnerabilità di traversing directory
- **CSRF Protection**: Verifica la protezione CSRF
- **Clickjacking Protection**: Controlla la protezione contro Clickjacking
- **Parameter Analysis**: Analizza i parametri dell'URL per vulnerabilità
- **JSON Results**: Salva i risultati in formato JSON
- **HTML Reports**: Genera report HTML professionali

## 🛠 Installazione

### Prerequisiti
- Python 3.6+
- pip (Python package installer)

### Installazione dipendenze
```bash
pip install requests
```

## ▶️ Utilizzo

### Base
```bash
python penetration_tester.py https://example.com
```

### Con opzioni
```bash
# Salva i risultati in JSON
python penetration_tester.py https://example.com --save-results

# Genera report HTML
python penetration_tester.py https://example.com --generate-html

# Salva entrambi i file
python penetration_tester.py https://example.com --save-results --generate-html

# Imposta timeout personalizzato
python penetration_tester.py https://example.com --timeout 15
```

### Opzioni disponibili
| Opzione | Descrizione |
|---------|-------------|
| `target` | URL della destinazione da testare |
| `--timeout` | Timeout delle richieste in secondi (default: 10) |
| `--save-results` | Salva i risultati in un file JSON |
| `--output-file` | Nome del file JSON di output |
| `--generate-html` | Genera un report HTML |
| `--html-file` | Nome del file HTML di output |

## 📊 Output

### JSON Output
I risultati vengono salvati in un file JSON con struttura:
```json
{
  "target": "https://example.com",
  "timestamp": "2026-10-28T10:30:45.123456",
  "tests": [
    {
      "test": "SQL Injection",
      "status": "passed",
      "details": []
    }
  ]
}
```

### HTML Report
Genera un report HTML con:
- Design professionale
- Colori distinti per stati diversi
- Informazioni dettagliate per ogni test
- Struttura chiara e leggibile

## 🔍 Test Effettuati

1. **SQL Injection**: Controlla errori SQL e payload comuni
2. **XSS**: Verifica payload XSS e pattern di scripting
3. **Directory Traversal**: Rileva tentativi di accesso a file sensibili
4. **CSRF Protection**: Verifica l'implementazione di protezione CSRF
5. **Clickjacking Protection**: Controlla header di protezione
6. **Parameter Analysis**: Analizza i parametri dell'URL

## 📁 File Generati

- **File JSON**: `penetration_test_YYYYMMDD_HHMMSS.json` (se --save-results)
- **File HTML**: `penetration_test_report_YYYYMMDD_HHMMSS.html` (se --generate-html)

## 🧪 Esempi d'Uso

### Test rapido
```bash
python penetration_tester.py https://mywebsite.com
```

### Test completo con salvataggio
```bash
python penetration_tester.py https://mywebsite.com --save-results --generate-html
```

### Test con timeout personalizzato
```bash
python penetration_tester.py https://mywebsite.com --timeout 20 --save-results
```

## 📦 Requisiti

- Python 3.6+
- requests (installabile con `pip install requests`)

## 📝 Note Tecniche

- Lo strumento effettua richieste HTTP alle URL specificate
- Non effettua attacchi maliziosi, ma verifica solo la presenza di vulnerabilità
- I test sono basati su pattern comuni e non garantiscono la completa copertura
- Per test più approfonditi si consiglia l'utilizzo di strumenti professionali come Burp Suite

## 🤝 Contribuire

Se desideri contribuire allo sviluppo di questo strumento:
1. Fork del repository
2. Crea un branch per la tua feature (`git checkout -b feature/nome-feature`)
3. Commit delle modifiche (`git commit -am 'Aggiunta nuova funzionalità'`)
4. Push del branch (`git push origin feature/nome-feature`)
5. Apri una Pull Request

## 📄 Licenza

Questo progetto è distribuito sotto licenza MIT - vedi il file [LICENSE](LICENSE) per maggiori informazioni.

## 👨‍💻 Autore

WebPenetrationTester - Tool di test di sicurezza per applicazioni web

---

> ⚠️ Ricorda: Questo strumento è per uso educativo e legittimo. Usa sempre il permesso esplicito prima di effettuare test su qualsiasi sistema.