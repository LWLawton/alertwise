"""
alertwise/enricher.py
======================
Threat Intelligence enrichment layer.

Supported sources:
  - VirusTotal  (file hash / domain / URL / IP)
  - AbuseIPDB   (IP reputation)
  - Shodan      (IP / host info)
  - AlienVault OTX (pulses / reputation)

Results are cached in the cache/ directory as JSON files, keyed by
indicator value. API keys are loaded from environment variables or a
.env file via python-dotenv.

Rate limiting:
  Each provider enforces a configurable sleep between calls to avoid
  hitting free-tier rate limits. Defaults are conservative.
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration – read from environment
# ---------------------------------------------------------------------------
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

CACHE_DIR = Path(os.getenv("ALERTWISE_CACHE_DIR", "cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Seconds to sleep between API calls per provider (respect free-tier limits)
RATE_LIMITS = {
    "virustotal": 15,   # VT free: 4 lookups/min → ~15s between calls
    "abuseipdb": 1,
    "shodan": 1,
    "otx": 0.5,
}

REQUEST_TIMEOUT = 10  # seconds


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_key(provider: str, indicator: str) -> str:
    """Generate a safe filename for caching a provider+indicator result."""
    safe = hashlib.md5(f"{provider}:{indicator}".encode()).hexdigest()
    return str(CACHE_DIR / f"{provider}_{safe}.json")


def _load_cache(provider: str, indicator: str) -> dict | None:
    path = _cache_key(provider, indicator)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.debug("Cache HIT  %s / %s", provider, indicator)
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_cache(provider: str, indicator: str, data: dict) -> None:
    path = _cache_key(provider, indicator)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        logger.warning("Could not write cache %s: %s", path, e)


def _error_result(provider: str, indicator: str, reason: str) -> dict:
    return {
        "provider": provider,
        "indicator": indicator,
        "error": reason,
        "score": 0,
        "tags": [],
        "raw": {},
    }


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}


def _vt_lookup(indicator_type: str, indicator: str) -> dict:
    """Query VirusTotal for a file hash, IP, domain, or URL."""
    if not VT_API_KEY:
        return _error_result("virustotal", indicator, "No API key configured")

    cached = _load_cache("virustotal", indicator)
    if cached:
        return cached

    base = "https://www.virustotal.com/api/v3"
    try:
        if indicator_type == "hash":
            url = f"{base}/files/{indicator}"
        elif indicator_type == "ip":
            url = f"{base}/ip_addresses/{indicator}"
        elif indicator_type == "domain":
            url = f"{base}/domains/{indicator}"
        elif indicator_type == "url":
            import base64
            encoded = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            url = f"{base}/urls/{encoded}"
        else:
            return _error_result("virustotal", indicator, f"Unknown type: {indicator_type}")

        resp = requests.get(url, headers=_vt_headers(), timeout=REQUEST_TIMEOUT)
        time.sleep(RATE_LIMITS["virustotal"])

        if resp.status_code == 404:
            result = {
                "provider": "virustotal",
                "indicator": indicator,
                "type": indicator_type,
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "score": 0,
                "tags": [],
                "raw": {},
            }
            _save_cache("virustotal", indicator, result)
            return result

        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        # Normalise score 0–100
        score = min(100, int(((malicious * 3 + suspicious) / total) * 100))

        tags = []
        if malicious > 0:
            tags.append("malicious")
        if suspicious > 0:
            tags.append("suspicious")
        names = attrs.get("popular_threat_classification", {})
        if names:
            label = names.get("suggested_threat_label", "")
            if label:
                tags.append(label)

        result = {
            "provider": "virustotal",
            "indicator": indicator,
            "type": indicator_type,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": sum(stats.values()),
            "score": score,
            "tags": tags,
            "raw": attrs,
        }
        _save_cache("virustotal", indicator, result)
        return result

    except requests.RequestException as e:
        logger.warning("VirusTotal request failed for %s: %s", indicator, e)
        return _error_result("virustotal", indicator, str(e))


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def _abuseipdb_lookup(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    if not ABUSEIPDB_API_KEY:
        return _error_result("abuseipdb", ip, "No API key configured")

    cached = _load_cache("abuseipdb", ip)
    if cached:
        return cached

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=REQUEST_TIMEOUT,
        )
        time.sleep(RATE_LIMITS["abuseipdb"])
        resp.raise_for_status()
        data = resp.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)
        categories = data.get("reports", [])
        tags = []
        if abuse_score >= 80:
            tags.append("high-abuse")
        elif abuse_score >= 40:
            tags.append("moderate-abuse")

        result = {
            "provider": "abuseipdb",
            "indicator": ip,
            "type": "ip",
            "found": True,
            "abuse_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "score": abuse_score,
            "tags": tags,
            "raw": data,
        }
        _save_cache("abuseipdb", ip, result)
        return result

    except requests.RequestException as e:
        logger.warning("AbuseIPDB request failed for %s: %s", ip, e)
        return _error_result("abuseipdb", ip, str(e))


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def _shodan_lookup(ip: str) -> dict:
    """Query Shodan for IP host information."""
    if not SHODAN_API_KEY:
        return _error_result("shodan", ip, "No API key configured")

    cached = _load_cache("shodan", ip)
    if cached:
        return cached

    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        time.sleep(RATE_LIMITS["shodan"])

        if resp.status_code == 404:
            result = {
                "provider": "shodan",
                "indicator": ip,
                "type": "ip",
                "found": False,
                "score": 0,
                "tags": [],
                "raw": {},
            }
            _save_cache("shodan", ip, result)
            return result

        resp.raise_for_status()
        data = resp.json()

        open_ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys()) if data.get("vulns") else []
        tags = data.get("tags", [])
        if vulns:
            tags.append("has-cves")

        # Score: more open ports + known vulns = higher risk
        score = min(100, len(open_ports) * 3 + len(vulns) * 20)

        result = {
            "provider": "shodan",
            "indicator": ip,
            "type": "ip",
            "found": True,
            "country": data.get("country_name", ""),
            "org": data.get("org", ""),
            "os": data.get("os", ""),
            "open_ports": open_ports[:20],
            "vulns": vulns[:10],
            "score": score,
            "tags": tags,
            "raw": {k: v for k, v in data.items() if k not in ("data",)},
        }
        _save_cache("shodan", ip, result)
        return result

    except requests.RequestException as e:
        logger.warning("Shodan request failed for %s: %s", ip, e)
        return _error_result("shodan", ip, str(e))


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def _otx_indicator_type(itype: str) -> str:
    """Map our internal type to OTX section path."""
    return {
        "ip": "IPv4",
        "domain": "domain",
        "hash": "file",
        "url": "url",
    }.get(itype, "IPv4")


def _otx_lookup(indicator_type: str, indicator: str) -> dict:
    """Query AlienVault OTX for pulses / reputation data."""
    if not OTX_API_KEY:
        return _error_result("otx", indicator, "No API key configured")

    cached = _load_cache("otx", indicator)
    if cached:
        return cached

    otx_type = _otx_indicator_type(indicator_type)
    sections = "general,reputation"
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/{sections}"

    try:
        resp = requests.get(
            url,
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        time.sleep(RATE_LIMITS["otx"])

        if resp.status_code in (400, 404):
            result = {
                "provider": "otx",
                "indicator": indicator,
                "type": indicator_type,
                "found": False,
                "pulse_count": 0,
                "score": 0,
                "tags": [],
                "raw": {},
            }
            _save_cache("otx", indicator, result)
            return result

        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        pulse_tags: list[str] = []
        for p in pulses[:5]:
            pulse_tags.extend(p.get("tags", []))

        # Reputation
        rep = data.get("reputation", {})
        rep_score = rep.get("score", 0) if rep else 0

        score = min(100, pulse_count * 10 + abs(rep_score))
        tags = list(set(pulse_tags))[:10]
        if pulse_count > 0:
            tags.insert(0, "otx-pulse-hit")

        result = {
            "provider": "otx",
            "indicator": indicator,
            "type": indicator_type,
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "reputation_score": rep_score,
            "score": score,
            "tags": tags,
            "raw": {
                "pulse_count": pulse_count,
                "reputation": rep,
                "sample_pulses": [p.get("name") for p in pulses[:3]],
            },
        }
        _save_cache("otx", indicator, result)
        return result

    except requests.RequestException as e:
        logger.warning("OTX request failed for %s: %s", indicator, e)
        return _error_result("otx", indicator, str(e))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ThreatEnricher:
    """
    Orchestrates multi-source threat intelligence enrichment for a
    normalised alert.  Returns an enrichment result dict that is merged
    back into the alert before scoring.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def enrich(self, alert: dict) -> dict[str, Any]:
        """
        Enrich an alert with threat intelligence.

        Returns:
            enrichment: dict with keys per indicator queried,
                        each containing a list of provider results.
        """
        if not self.enabled:
            return {"enabled": False, "results": {}, "max_score": 0}

        indicators = alert.get("indicators", {})
        results: dict[str, list] = {}
        max_score = 0

        # -- IPs -----------------------------------------------------------------
        all_ips = list(set(
            indicators.get("src_ips", []) +
            indicators.get("dest_ips", []) +
            indicators.get("ips", [])
        ))
        for ip in all_ips[:5]:  # Limit to 5 IPs per alert
            ip_results = []
            if ABUSEIPDB_API_KEY:
                r = _abuseipdb_lookup(ip)
                ip_results.append(r)
                max_score = max(max_score, r.get("score", 0))

            if SHODAN_API_KEY:
                r = _shodan_lookup(ip)
                ip_results.append(r)
                max_score = max(max_score, r.get("score", 0))

            if VT_API_KEY:
                r = _vt_lookup("ip", ip)
                ip_results.append(r)
                max_score = max(max_score, r.get("score", 0))

            if OTX_API_KEY:
                r = _otx_lookup("ip", ip)
                ip_results.append(r)
                max_score = max(max_score, r.get("score", 0))

            if ip_results:
                results[f"ip:{ip}"] = ip_results

        # -- File hashes ---------------------------------------------------------
        for h in indicators.get("file_hashes", [])[:3]:
            hash_results = []
            if VT_API_KEY:
                r = _vt_lookup("hash", h)
                hash_results.append(r)
                max_score = max(max_score, r.get("score", 0))
            if OTX_API_KEY:
                r = _otx_lookup("hash", h)
                hash_results.append(r)
                max_score = max(max_score, r.get("score", 0))
            if hash_results:
                results[f"hash:{h}"] = hash_results

        # -- Domains -------------------------------------------------------------
        for domain in indicators.get("domains", [])[:3]:
            dom_results = []
            if VT_API_KEY:
                r = _vt_lookup("domain", domain)
                dom_results.append(r)
                max_score = max(max_score, r.get("score", 0))
            if OTX_API_KEY:
                r = _otx_lookup("domain", domain)
                dom_results.append(r)
                max_score = max(max_score, r.get("score", 0))
            if dom_results:
                results[f"domain:{domain}"] = dom_results

        # -- URLs ----------------------------------------------------------------
        for url in indicators.get("urls", [])[:2]:
            url_results = []
            if VT_API_KEY:
                r = _vt_lookup("url", url)
                url_results.append(r)
                max_score = max(max_score, r.get("score", 0))
            if url_results:
                results[f"url:{url}"] = url_results

        logger.info(
            "Enrichment complete for alert %s — %d indicator(s) queried, max_score=%d",
            alert.get("alert_id"), len(results), max_score,
        )
        return {
            "enabled": True,
            "results": results,
            "max_score": max_score,
            "indicator_count": len(results),
        }
