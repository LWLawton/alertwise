"""
alertwise/normalizer.py
========================
Normalizes raw alert JSON into a consistent internal schema.
Handles missing/optional fields gracefully and extracts key indicators
(IPs, hashes, domains, URLs, usernames) from the entities array.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Regex patterns for indicator extraction
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'>]+")

# Severity normalisation map
_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "med": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "unknown": "Unknown",
}


def normalize_severity(raw: str | None) -> str:
    """Return a canonical severity string."""
    if not raw:
        return "Unknown"
    return _SEVERITY_MAP.get(raw.strip().lower(), raw.strip().capitalize())


def extract_indicators_from_text(text: str) -> dict[str, list[str]]:
    """
    Extract IPs, hashes, domains, and URLs from free-form text.
    Returns a dict with lists keyed by indicator type.
    """
    return {
        "ips": list(set(_IP_RE.findall(text))),
        "md5": list(set(_MD5_RE.findall(text))),
        "sha1": list(set(_SHA1_RE.findall(text))),
        "sha256": list(set(_SHA256_RE.findall(text))),
        "domains": list(set(_DOMAIN_RE.findall(text))),
        "urls": list(set(_URL_RE.findall(text))),
    }


def _entity_value(entity: dict, *keys: str) -> str | None:
    """Return the first non-empty value found in entity for the given keys."""
    for k in keys:
        v = entity.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return None


def parse_entities(entities: list[dict]) -> dict[str, list[str]]:
    """
    Walk the entities array and extract typed indicators.
    Recognises entity types: host, ip, process, user, file, domain, url, hash.
    """
    indicators: dict[str, list[str]] = {
        "src_ips": [],
        "dest_ips": [],
        "ips": [],
        "hostnames": [],
        "usernames": [],
        "processes": [],
        "file_hashes": [],
        "domains": [],
        "urls": [],
        "file_names": [],
    }

    for entity in entities:
        etype = str(entity.get("type", "")).lower()

        # --- IP entities ---
        if etype in ("ip", "ipaddress", "network"):
            ip = _entity_value(entity, "value", "ip", "address")
            direction = str(entity.get("direction", "")).lower()
            if ip:
                if direction == "src" or entity.get("is_source"):
                    indicators["src_ips"].append(ip)
                elif direction in ("dst", "dest", "destination") or entity.get("is_dest"):
                    indicators["dest_ips"].append(ip)
                else:
                    indicators["ips"].append(ip)

        # --- Host entities ---
        elif etype in ("host", "hostname", "endpoint", "device"):
            hostname = _entity_value(entity, "value", "hostname", "name", "fqdn")
            if hostname:
                indicators["hostnames"].append(hostname)
            # Hosts may also carry embedded IP
            for field in ("ip", "address", "ip_address"):
                ip = entity.get(field)
                if ip:
                    indicators["ips"].append(str(ip))

        # --- User entities ---
        elif etype in ("user", "account", "identity"):
            user = _entity_value(entity, "value", "username", "name", "account")
            if user:
                indicators["usernames"].append(user)

        # --- Process entities ---
        elif etype in ("process", "proc"):
            proc = _entity_value(entity, "value", "name", "process_name", "cmdline")
            if proc:
                indicators["processes"].append(proc)

        # --- File entities ---
        elif etype in ("file", "filename"):
            fname = _entity_value(entity, "value", "name", "file_name", "path")
            if fname:
                indicators["file_names"].append(fname)
            for field in ("md5", "sha1", "sha256", "hash"):
                h = entity.get(field)
                if h:
                    indicators["file_hashes"].append(str(h))

        # --- Hash entities ---
        elif etype in ("hash", "filehash", "ioc_hash"):
            h = _entity_value(entity, "value", "hash", "md5", "sha256", "sha1")
            if h:
                indicators["file_hashes"].append(h)

        # --- Domain entities ---
        elif etype in ("domain", "fqdn", "dns"):
            domain = _entity_value(entity, "value", "domain", "name", "fqdn")
            if domain:
                indicators["domains"].append(domain)

        # --- URL entities ---
        elif etype in ("url", "uri", "link"):
            url = _entity_value(entity, "value", "url", "uri")
            if url:
                indicators["urls"].append(url)

        else:
            # Generic fallback — try to find any known indicator fields
            for field in ("ip", "src_ip", "dest_ip", "source_ip", "destination_ip"):
                v = entity.get(field)
                if v:
                    indicators["ips"].append(str(v))
            for field in ("hostname", "host", "fqdn"):
                v = entity.get(field)
                if v:
                    indicators["hostnames"].append(str(v))
            for field in ("username", "user", "account"):
                v = entity.get(field)
                if v:
                    indicators["usernames"].append(str(v))
            for field in ("md5", "sha1", "sha256", "hash", "file_hash"):
                v = entity.get(field)
                if v:
                    indicators["file_hashes"].append(str(v))

    # Deduplicate all lists
    return {k: list(set(v)) for k, v in indicators.items()}


def normalize_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a raw alert JSON object into the AlertWise internal schema.

    Internal schema keys:
        alert_id        – unique identifier (from metadata or generated)
        event_type      – e.g. "Alert"
        title           – alert title / rule name
        description     – human-readable description
        severity        – normalised severity string
        raw_severity    – original severity value
        source_product  – e.g. "Splunk", "Crowdstrike"
        rule_id         – SIEM rule/signature ID
        timestamp       – ISO timestamp string
        mitre_technique – MITRE ATT&CK technique ID(s)
        mitre_tactic    – MITRE ATT&CK tactic(s)
        indicators      – extracted observables dict
        entities        – raw entities list
        raw             – original alert dict (preserved for reporting)
    """
    meta = raw.get("metadata", {}) or {}
    summary = raw.get("alert_summary", {}) or {}
    mitre = raw.get("mitre_attack", {}) or {}
    entities = raw.get("entities", []) or []

    # -- Identity ----------------------------------------------------------------
    alert_id = (
        meta.get("alert_id")
        or meta.get("id")
        or raw.get("id")
        or raw.get("alert_id")
        or f"AW-{abs(hash(str(raw))) % 100000:05d}"
    )

    # -- Narrative ---------------------------------------------------------------
    title = (
        summary.get("title")
        or raw.get("title")
        or raw.get("rule_name")
        or "Untitled Alert"
    )
    description = (
        summary.get("description")
        or raw.get("description")
        or raw.get("message")
        or ""
    )

    # -- Severity ----------------------------------------------------------------
    raw_sev = (
        summary.get("severity")
        or raw.get("severity")
        or meta.get("severity")
        or "Unknown"
    )
    severity = normalize_severity(raw_sev)

    # -- Source / rule info ------------------------------------------------------
    source_product = (
        meta.get("source_product")
        or meta.get("product")
        or raw.get("source_product")
        or raw.get("product")
        or "Unknown"
    )
    rule_id = (
        meta.get("rule_id")
        or meta.get("signature_id")
        or raw.get("rule_id")
        or raw.get("signature_id")
        or ""
    )
    timestamp = (
        meta.get("timestamp")
        or meta.get("event_time")
        or raw.get("timestamp")
        or raw.get("event_time")
        or ""
    )

    # -- MITRE -------------------------------------------------------------------
    technique = mitre.get("technique_id") or mitre.get("technique") or ""
    tactic = mitre.get("tactic") or mitre.get("tactics") or ""
    if isinstance(tactic, list):
        tactic = ", ".join(tactic)

    # -- Indicators from entities ------------------------------------------------
    indicators = parse_entities(entities)

    # Also scan title + description for embedded indicators
    text_iocs = extract_indicators_from_text(f"{title} {description}")
    for key in ("ips", "domains", "urls", "md5", "sha1", "sha256"):
        indicators.setdefault(key, [])
        indicators[key] = list(set(indicators[key] + text_iocs.get(key, [])))

    # Consolidate file_hashes with any inline hash hits
    for hash_key in ("md5", "sha1", "sha256"):
        indicators["file_hashes"] = list(
            set(indicators["file_hashes"] + indicators.pop(hash_key, []))
        )

    normalised = {
        "alert_id": str(alert_id),
        "event_type": raw.get("event_type", "Alert"),
        "title": title,
        "description": description,
        "severity": severity,
        "raw_severity": raw_sev,
        "source_product": source_product,
        "rule_id": rule_id,
        "timestamp": timestamp,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "indicators": indicators,
        "entities": entities,
        "raw": raw,
    }

    logger.debug("Normalised alert %s: severity=%s, indicators=%s", alert_id, severity, indicators)
    return normalised
