"""
alertwise/suppressor.py
========================
Configurable suppression / whitelisting engine.

Rules are loaded from suppression_rules.json and evaluated against each
normalised alert.  Each rule has a type, match criteria, and an action.

Supported rule types:
  - ip_whitelist         : suppress if any indicator IP is in the whitelist
  - ip_range             : suppress if any indicator IP is in a CIDR range
  - domain_whitelist     : suppress if any domain indicator is whitelisted
  - title_contains       : suppress if alert title contains a substring
  - title_regex          : suppress if alert title matches a regex
  - severity_threshold   : suppress if severity is at or below a threshold
  - rule_id              : suppress if rule/signature ID matches
  - source_product       : suppress if source product matches
  - frequency_threshold  : suppress if same rule_id seen N+ times (requires freq map)
  - user_whitelist       : suppress if all actors are internal/known-safe users
  - process_whitelist    : suppress if process name is whitelisted

Analyst decision overrides are loaded from decisions.json.  An override
always takes precedence over automatic suppression.
"""

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default rule file shipped with the project
DEFAULT_RULES_PATH = "data/suppression_rules.json"
DEFAULT_DECISIONS_PATH = "data/decisions.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_in_range(ip_str: str, cidr: str) -> bool:
    """Return True if ip_str falls within the given CIDR range."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _severity_rank(severity: str) -> int:
    """Map severity string to ordinal for comparison."""
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "med": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
        "unknown": 0,
    }.get(severity.lower(), 0)


# ---------------------------------------------------------------------------
# Rule evaluator
# ---------------------------------------------------------------------------

class SuppressionEngine:
    """
    Loads and evaluates suppression rules against normalised alerts.
    """

    def __init__(
        self,
        rules_path: str = DEFAULT_RULES_PATH,
        decisions_path: str = DEFAULT_DECISIONS_PATH,
    ) -> None:
        self.rules: list[dict] = []
        self.decisions: dict[str, dict] = {}
        self._load_rules(rules_path)
        self._load_decisions(decisions_path)
        self._freq_map: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Load helpers
    # ------------------------------------------------------------------

    def _load_rules(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning("Suppression rules file not found: %s — no rules loaded", path)
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.rules = data if isinstance(data, list) else data.get("rules", [])
            logger.info("Loaded %d suppression rule(s) from %s", len(self.rules), path)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load suppression rules: %s", e)

    def _load_decisions(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.debug("Decisions file not found: %s — no overrides loaded", path)
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Keyed by alert_id or rule_id
            self.decisions = {str(k): v for k, v in data.items()}
            logger.info("Loaded %d analyst decision override(s)", len(self.decisions))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load decisions: %s", e)

    # ------------------------------------------------------------------
    # Frequency tracking
    # ------------------------------------------------------------------

    def record_alert(self, alert: dict) -> None:
        """Track frequency of rule IDs across alerts in this run."""
        rule_id = alert.get("rule_id") or alert.get("title", "")
        if rule_id:
            self._freq_map[rule_id] = self._freq_map.get(rule_id, 0) + 1

    def get_frequency(self, rule_id: str) -> int:
        return self._freq_map.get(rule_id, 0)

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def evaluate(self, alert: dict) -> dict[str, Any]:
        """
        Evaluate all suppression rules against a single alert.

        Returns:
            {
                "suppressed": bool,
                "matched_rules": list[str],   # names/IDs of matched rules
                "override": dict | None,       # analyst override if present
                "reason": str,                 # human-readable explanation
            }
        """
        indicators = alert.get("indicators", {})
        title = alert.get("title", "")
        severity = alert.get("severity", "Unknown")
        rule_id = alert.get("rule_id", "")
        alert_id = alert.get("alert_id", "")
        source_product = alert.get("source_product", "")

        all_ips = list(set(
            indicators.get("src_ips", []) +
            indicators.get("dest_ips", []) +
            indicators.get("ips", [])
        ))
        domains = indicators.get("domains", [])
        usernames = indicators.get("usernames", [])
        processes = indicators.get("processes", [])

        matched: list[str] = []

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            rtype = rule.get("type", "")
            rname = rule.get("name", rtype)

            # ---- ip_whitelist ------------------------------------------------
            if rtype == "ip_whitelist":
                whitelist = rule.get("values", [])
                for ip in all_ips:
                    if ip in whitelist:
                        matched.append(rname)
                        break

            # ---- ip_range ----------------------------------------------------
            elif rtype == "ip_range":
                ranges = rule.get("ranges", [])
                for ip in all_ips:
                    for cidr in ranges:
                        if _ip_in_range(ip, cidr):
                            matched.append(rname)
                            break

            # ---- domain_whitelist --------------------------------------------
            elif rtype == "domain_whitelist":
                whitelist = rule.get("values", [])
                for dom in domains:
                    if dom in whitelist:
                        matched.append(rname)
                        break

            # ---- title_contains ----------------------------------------------
            elif rtype == "title_contains":
                substrings = rule.get("values", [])
                for s in substrings:
                    if s.lower() in title.lower():
                        matched.append(rname)
                        break

            # ---- title_regex -------------------------------------------------
            elif rtype == "title_regex":
                patterns = rule.get("patterns", [])
                for pat in patterns:
                    try:
                        if re.search(pat, title, re.IGNORECASE):
                            matched.append(rname)
                            break
                    except re.error:
                        logger.warning("Invalid regex in rule %s: %s", rname, pat)

            # ---- severity_threshold ------------------------------------------
            elif rtype == "severity_threshold":
                threshold = rule.get("max_severity", "low")
                if _severity_rank(severity) <= _severity_rank(threshold):
                    matched.append(rname)

            # ---- rule_id -----------------------------------------------------
            elif rtype == "rule_id":
                ids = rule.get("values", [])
                if rule_id in ids:
                    matched.append(rname)

            # ---- source_product ----------------------------------------------
            elif rtype == "source_product":
                products = [p.lower() for p in rule.get("values", [])]
                if source_product.lower() in products:
                    matched.append(rname)

            # ---- frequency_threshold -----------------------------------------
            elif rtype == "frequency_threshold":
                key = rule_id or title
                limit = rule.get("max_count", 10)
                freq = self.get_frequency(key)
                if freq >= limit:
                    matched.append(f"{rname} (seen {freq}x)")

            # ---- user_whitelist ----------------------------------------------
            elif rtype == "user_whitelist":
                whitelist = [u.lower() for u in rule.get("values", [])]
                if usernames and all(u.lower() in whitelist for u in usernames):
                    matched.append(rname)

            # ---- process_whitelist -------------------------------------------
            elif rtype == "process_whitelist":
                whitelist = [p.lower() for p in rule.get("values", [])]
                if processes and all(p.lower() in whitelist for p in processes):
                    matched.append(rname)

        # ---- Analyst overrides -----------------------------------------------
        override = (
            self.decisions.get(alert_id)
            or self.decisions.get(rule_id)
            or None
        )

        suppressed = len(matched) > 0

        # Override can force or prevent suppression
        if override:
            action = override.get("action", "").lower()
            if action in ("suppress", "benign"):
                suppressed = True
                matched.append(f"analyst-override:{override.get('analyst','')}")
            elif action in ("escalate", "investigate"):
                suppressed = False  # Don't suppress even if rules matched
                matched = [m for m in matched if "analyst-override" in m]

        reason = ""
        if suppressed and matched:
            reason = f"Suppressed by: {', '.join(matched)}"
        elif not suppressed and matched:
            reason = f"Rules matched but analyst override prevents suppression: {', '.join(matched)}"
        elif override:
            reason = f"Analyst override: {override.get('reason', override.get('action', ''))}"

        return {
            "suppressed": suppressed,
            "matched_rules": matched,
            "override": override,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Tuning recommendations
    # ------------------------------------------------------------------

    def get_noisy_rules(self, threshold: int = 3) -> list[dict]:
        """
        Return a list of rule IDs that have fired more than `threshold` times.
        Useful for SIEM tuning recommendations.
        """
        noisy = []
        for rule_id, count in sorted(self._freq_map.items(), key=lambda x: -x[1]):
            if count >= threshold:
                noisy.append({"rule_id": rule_id, "count": count})
        return noisy
