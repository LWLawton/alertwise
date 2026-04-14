"""
alertwise/scorer.py
====================
Heuristic risk scoring engine for AlertWise.

Scoring model (0–100):
  - Base severity score       (0–35)
  - Enrichment / TI score     (0–40)
  - MITRE ATT&CK bonus        (0–10)
  - Context factors           (0–15)
    * Internal-only traffic   (-10)
    * Known-bad processes     (+5)
    * Multiple entities       (+5)
    * Asset criticality       (+5)

Final triage decision:
  - score >= 75  → ESCALATE
  - score >= 45  → INVESTIGATE
  - score >= 20  → MONITOR
  - suppressed   → SUPPRESS
  - score <  20  → BENIGN
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_BASE = {
    "critical": 35,
    "high": 28,
    "medium": 18,
    "med": 18,
    "low": 8,
    "info": 3,
    "informational": 3,
    "unknown": 5,
}

MITRE_HIGH_IMPACT = {
    # Execution
    "T1059", "T1059.001", "T1059.003",
    # Persistence
    "T1053", "T1547", "T1078",
    # Privilege escalation
    "T1055", "T1134", "T1068",
    # Defense evasion
    "T1562", "T1070", "T1027",
    # Credential access
    "T1003", "T1552", "T1558",
    # Lateral movement
    "T1021", "T1570",
    # Exfiltration
    "T1041", "T1567", "T1048",
    # Command and control
    "T1071", "T1095", "T1572",
    # Impact
    "T1485", "T1486", "T1490",
}

SUSPICIOUS_PROCESSES = {
    "mimikatz", "meterpreter", "cobalt", "beacon", "psexec", "wce",
    "procdump", "lsass", "rubeus", "bloodhound", "sharphound",
    "powersploit", "empire", "invoke-", "certutil", "regsvr32",
    "mshta", "wscript", "cscript", "rundll32", "schtasks",
}

# RFC1918 / loopback ranges – traffic within these is considered "internal"
INTERNAL_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
]

import ipaddress as _ipmod


def _is_internal_ip(ip: str) -> bool:
    try:
        addr = _ipmod.ip_address(ip)
        for cidr in INTERNAL_RANGES:
            if addr in _ipmod.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _extract_technique_ids(raw: str) -> list[str]:
    """Pull MITRE technique IDs like T1059.001 out of a string."""
    return re.findall(r"T\d{4}(?:\.\d{3})?", raw.upper())


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class AlertScorer:
    """Compute a risk score and triage recommendation for a single alert."""

    def score(self, alert: dict, enrichment: dict, suppression: dict) -> dict[str, Any]:
        """
        Parameters:
            alert      – normalised alert dict
            enrichment – result from ThreatEnricher.enrich()
            suppression – result from SuppressionEngine.evaluate()

        Returns:
            scoring dict with keys:
                score         – int 0–100
                decision      – ESCALATE / INVESTIGATE / MONITOR / SUPPRESS / BENIGN
                confidence    – High / Medium / Low
                breakdown     – dict of score components
                reasoning     – list of human-readable reason strings
        """
        severity = alert.get("severity", "Unknown")
        indicators = alert.get("indicators", {})
        mitre_technique = alert.get("mitre_technique", "")
        mitre_tactic = alert.get("mitre_tactic", "")
        processes = indicators.get("processes", [])

        reasoning: list[str] = []
        breakdown: dict[str, int] = {}

        # ----------------------------------------------------------------
        # 1. Base severity score
        # ----------------------------------------------------------------
        base = SEVERITY_BASE.get(severity.lower(), 5)
        breakdown["base_severity"] = base
        reasoning.append(f"Base severity [{severity}] → +{base} pts")

        # ----------------------------------------------------------------
        # 2. Threat intelligence enrichment score
        # ----------------------------------------------------------------
        ti_score = 0
        if enrichment.get("enabled"):
            raw_max = enrichment.get("max_score", 0)
            # Scale TI score to our 0–40 range
            ti_score = min(40, int(raw_max * 0.40))
            if ti_score > 0:
                reasoning.append(f"TI enrichment (max indicator score {raw_max}/100) → +{ti_score} pts")

            # Tag-based bonuses from enrichment results
            for key, results in enrichment.get("results", {}).items():
                for r in results:
                    for tag in r.get("tags", []):
                        if tag in ("malicious", "high-abuse", "otx-pulse-hit", "has-cves"):
                            extra = 5
                            ti_score = min(40, ti_score + extra)
                            reasoning.append(f"  ↳ [{r['provider']}] tag '{tag}' on {key} → +{extra} pts")
                            break
        else:
            reasoning.append("TI enrichment disabled — no enrichment score applied")
        breakdown["ti_enrichment"] = ti_score

        # ----------------------------------------------------------------
        # 3. MITRE ATT&CK bonus
        # ----------------------------------------------------------------
        mitre_bonus = 0
        technique_ids = _extract_technique_ids(mitre_technique)
        for tid in technique_ids:
            if tid in MITRE_HIGH_IMPACT:
                mitre_bonus = min(mitre_bonus + 5, 10)
                reasoning.append(f"MITRE high-impact technique {tid} → +5 pts")
        if mitre_tactic:
            if any(t in mitre_tactic.lower() for t in ("exfiltration", "impact", "command")):
                mitre_bonus = min(mitre_bonus + 3, 10)
                reasoning.append(f"MITRE high-risk tactic [{mitre_tactic}] → +3 pts")
        breakdown["mitre_bonus"] = mitre_bonus

        # ----------------------------------------------------------------
        # 4. Context factors
        # ----------------------------------------------------------------
        context_score = 0

        # Suspicious processes
        for proc in processes:
            proc_lower = proc.lower()
            for sus in SUSPICIOUS_PROCESSES:
                if sus in proc_lower:
                    context_score = min(context_score + 5, 15)
                    reasoning.append(f"Suspicious process detected: '{proc}' → +5 pts")
                    break

        # Multiple entities / spread
        entity_count = len(alert.get("entities", []))
        if entity_count >= 5:
            context_score = min(context_score + 3, 15)
            reasoning.append(f"High entity count ({entity_count}) → +3 pts")
        elif entity_count >= 3:
            context_score = min(context_score + 1, 15)
            reasoning.append(f"Multiple entities ({entity_count}) → +1 pt")

        # All IPs are internal → reduce risk
        all_ips = (
            indicators.get("src_ips", []) +
            indicators.get("dest_ips", []) +
            indicators.get("ips", [])
        )
        if all_ips and all(_is_internal_ip(ip) for ip in all_ips):
            context_score = max(context_score - 10, -15)
            reasoning.append(f"All IPs are internal RFC1918 → -10 pts")
        elif any(not _is_internal_ip(ip) for ip in all_ips):
            context_score = min(context_score + 3, 15)
            reasoning.append("External IP detected → +3 pts")

        breakdown["context_factors"] = context_score

        # ----------------------------------------------------------------
        # 5. Total score
        # ----------------------------------------------------------------
        total = max(0, min(100, base + ti_score + mitre_bonus + context_score))
        breakdown["total"] = total

        # ----------------------------------------------------------------
        # 6. Suppression check
        # ----------------------------------------------------------------
        if suppression.get("suppressed"):
            decision = "SUPPRESS"
            confidence = "High"
            reason_str = suppression.get("reason", "Matched suppression rule")
            reasoning.insert(0, f"⛔ Suppressed: {reason_str}")
        else:
            decision, confidence = self._decision_from_score(total, enrichment)

        logger.debug(
            "Alert %s scored %d → %s (breakdown=%s)",
            alert.get("alert_id"), total, decision, breakdown,
        )

        return {
            "score": total,
            "decision": decision,
            "confidence": confidence,
            "breakdown": breakdown,
            "reasoning": reasoning,
        }

    @staticmethod
    def _decision_from_score(score: int, enrichment: dict) -> tuple[str, str]:
        """Derive triage decision and confidence from numeric score."""
        has_ti = enrichment.get("enabled") and enrichment.get("indicator_count", 0) > 0

        if score >= 75:
            return "ESCALATE", "High"
        elif score >= 55:
            return "ESCALATE", "Medium" if not has_ti else "High"
        elif score >= 40:
            return "INVESTIGATE", "Medium"
        elif score >= 20:
            return "MONITOR", "Low"
        else:
            return "BENIGN", "High" if score < 10 else "Medium"
