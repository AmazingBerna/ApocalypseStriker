"""Dati sulle minacce: catalogo CISA KEV e punteggi EPSS di FIRST.

I due file vengono scaricati sulla macchina che lancia lo script (non sul target) e tenuti
in cache per THREAT_INTEL_MAX_AGE_HOURS. Si scaricano interi, invece di interrogare un'API
CVE per CVE, così nessun servizio esterno viene a sapere quali vulnerabilità ha la macchina.

assess_cves() trasforma un elenco di CVE nella probabilità del finding che le contiene.
"""
import csv
import gzip
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from .config import (
    KEV_URL, EPSS_URL, THREAT_INTEL_MAX_AGE_HOURS, THREAT_INTEL_TIMEOUT,
    KEV_PROBABILITY, EPSS_PROBABILITY, EPSS_MIN_PROBABILITY, CVSS_PROBABILITY,
)

USER_AGENT = "ApocalypseScan (risk assessment; +https://github.com/AmazingBerna/ApocalypseScan)"
KEV_FILE = "known_exploited_vulnerabilities.json"
EPSS_FILE = "epss_scores-current.csv.gz"

# A parità di probabilità vince la fonte più affidabile
BASIS_RANK = {"kev": 3, "epss": 2, "cvss": 1, "euristica": 0}


class ThreatIntelError(Exception):
    """I dati KEV/EPSS non sono disponibili: la scansione non può proseguire."""


def cache_dir():
    """~/.cache/apocalypsescan (o $XDG_CACHE_HOME/apocalypsescan)."""
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "apocalypsescan"


def _download(url, dest, timeout):
    """Scarica url in dest passando da un file temporaneo: un download interrotto non
    lascia in cache un file a metà."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_name(dest.name + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, open(tmp, "wb") as out:
            while chunk := response.read(1 << 16):
                out.write(chunk)
        os.replace(tmp, dest)
    except (urllib.error.URLError, OSError) as error:
        tmp.unlink(missing_ok=True)
        reason = getattr(error, "reason", error)
        raise ThreatIntelError(f"download di {url} non riuscito: {reason}") from error


def _ensure_file(url, name, folder, max_age, timeout):
    """Restituisce (percorso, 'cache' | 'download') di un file aggiornato."""
    path = folder / name
    if path.exists() and time.time() - path.stat().st_mtime < max_age:
        return path, "cache"
    _download(url, path, timeout)
    return path, "download"


def _writable_cache():
    """La cartella di cache, oppure una cartella temporanea se non è scrivibile."""
    folder = cache_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".scrivibile"
        probe.touch()
        probe.unlink()
        return folder
    except OSError:
        return Path(tempfile.mkdtemp(prefix="apocalypsescan_intel_"))


def _read_kev(path):
    try:
        data = json.loads(path.read_bytes().decode("utf-8", errors="replace"))
        cves = {v["cveID"] for v in data["vulnerabilities"]}
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ThreatIntelError(f"catalogo KEV non valido ({path}): {error}") from error
    meta = {"catalog_version": data.get("catalogVersion"), "date_released": data.get("dateReleased"),
            "count": len(cves)}
    return cves, meta


def _read_epss_header(path):
    """Prima riga del CSV EPSS: '#model_version:v2026.06.15,score_date:2026-10-15T12:03:56Z'."""
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            comment, header = f.readline().strip(), f.readline().strip()
    except (OSError, EOFError, UnicodeDecodeError) as error:
        raise ThreatIntelError(f"file EPSS non valido ({path}): {error}") from error
    if not comment.startswith("#") or not header.startswith("cve,epss"):
        raise ThreatIntelError(f"file EPSS in un formato inatteso ({path})")
    meta = dict(part.split(":", 1) for part in comment[1:].split(",") if ":" in part)
    return {"model_version": meta.get("model_version"), "score_date": meta.get("score_date")}


class ThreatIntel:
    """KEV in memoria (poche migliaia di CVE); EPSS letto dal file solo per le CVE richieste,
    perché il file completo ne contiene centinaia di migliaia."""

    def __init__(self, kev, kev_meta, epss_path, epss_meta, sources):
        self.kev = kev
        self.kev_meta = kev_meta
        self.epss_path = epss_path
        self.epss_meta = epss_meta
        self.sources = sources
        self._epss = {}   # cve -> (epss, percentile) oppure None se non presente

    def epss(self, cves):
        """{cve: (epss, percentile) | None} per le CVE indicate."""
        missing = {c for c in cves if c not in self._epss}
        if missing:
            with gzip.open(self.epss_path, "rt", encoding="utf-8") as f:
                next(f)   # commento con versione del modello e data
                for row in csv.DictReader(f):
                    if row["cve"] in missing:
                        self._epss[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            for cve in missing:
                self._epss.setdefault(cve, None)
        return {c: self._epss[c] for c in cves}

    def meta(self):
        """Informazioni sui dati usati, per il report."""
        return {
            "kev": {**self.kev_meta, "source": self.sources["kev"], "url": KEV_URL},
            "epss": {**self.epss_meta, "source": self.sources["epss"], "url": EPSS_URL},
        }


def load_threat_intel(max_age_hours=THREAT_INTEL_MAX_AGE_HOURS, timeout=THREAT_INTEL_TIMEOUT):
    """Scarica (o prende dalla cache) KEV ed EPSS. Solleva ThreatIntelError se non ci riesce."""
    folder = _writable_cache()
    max_age = max_age_hours * 3600
    kev_path, kev_source = _ensure_file(KEV_URL, KEV_FILE, folder, max_age, timeout)
    epss_path, epss_source = _ensure_file(EPSS_URL, EPSS_FILE, folder, max_age, timeout)
    kev, kev_meta = _read_kev(kev_path)
    epss_meta = _read_epss_header(epss_path)
    return ThreatIntel(kev, kev_meta, epss_path, epss_meta,
                       {"kev": kev_source, "epss": epss_source})


def epss_probability(score):
    for minimum, probability in EPSS_PROBABILITY:
        if score >= minimum:
            return probability
    return EPSS_MIN_PROBABILITY


def cvss_probability(vector):
    """Probabilità dal vettore CVSS v3 o v4 (es. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/...'), o None."""
    if not vector:
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    av = metrics.get("AV")
    if av == "N":
        unauth = metrics.get("PR") == "N" and metrics.get("UI") == "N"
        return CVSS_PROBABILITY["network_unauth" if unauth else "network"]
    if av in ("A", "L"):
        return CVSS_PROBABILITY["adjacent_local"]
    if av == "P":
        return CVSS_PROBABILITY["physical"]
    return None


def assess_cves(intel, cves, default, cvss_vectors=None, cvss_scores=None, max_probability=None):
    """Probabilità di un finding a partire dalle sue CVE: vale quella della CVE peggiore.

    Per ogni CVE: 5 se è nel KEV, altrimenti dalla soglia EPSS, altrimenti dal vettore CVSS.
    Se nessuna CVE ha dati, si usa default (il valore euristico della fonte).
    Restituisce (probabilità, campi aggiuntivi del finding)."""
    cvss_vectors = cvss_vectors or {}
    cvss_scores = cvss_scores or {}
    scores = [s for s in (cvss_scores.get(c) for c in cves) if s is not None]
    fields = {"probability_basis": "euristica", "probability_cve": None, "epss": None,
              "epss_percentile": None, "kev": None, "cvss": max(scores) if scores else None}
    if intel is None or not cves:
        return default, fields

    epss = intel.epss(cves)
    kev = [c for c in cves if c in intel.kev]
    known = [e for e in epss.values() if e is not None]
    fields["kev"] = bool(kev)
    if known:
        fields["epss"], fields["epss_percentile"] = max(known)

    best = None   # (probabilità, rango della fonte, epss, cve, fonte)
    for cve in cves:
        if cve in intel.kev:
            candidate = (KEV_PROBABILITY, "kev")
        elif epss[cve] is not None:
            candidate = (epss_probability(epss[cve][0]), "epss")
        elif (p := cvss_probability(cvss_vectors.get(cve))) is not None:
            candidate = (p, "cvss")
        else:
            continue
        key = (candidate[0], BASIS_RANK[candidate[1]], (epss[cve] or (0,))[0], cve, candidate[1])
        best = max(best, key) if best else key

    if best is None:
        return default, fields
    probability, _, _, cve, basis = best
    if max_probability is not None:
        probability = min(probability, max_probability)
    fields.update(probability_basis=basis, probability_cve=cve)
    return probability, fields
