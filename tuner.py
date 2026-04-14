"""
alertwise/tuner.py
===================
SIEM Tuning Recommendations Engine (v1).

Analyses a collection of processed alerts to identify:
  - Noisy rules (high firing frequency)
  - Suppression candidates
  - Whitelist suggestions
  - Rule refinement opportunities
  - Severity miscalibration hints

All analysis is heuristic — no ML required.
"""

import logging
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)

# Thresholds
NOISY_RULE_THRESHOLD = 3        # Rule fired >= 3 times → noisy candidate
HIGH_SUPPRESS_RATIO = 0.7       # Rule suppressed >= 70% of time → whitelist candidate
SEVERITY_MISMATCH_SCORE = 20    # Low-scored but High-severity alert → miscalibration


class SIEMTuner:
    """
    Accepts a list of fully processed alert results and produces
    actionable SIEM tuning recommendations.
    """

    def analyze(self, results: list[dict]) -> dict[str, Any]:
        """
        Analyse processed results and return tuning recommendations.

        Parameters:
            results – list of dicts from AlertWisePipeline.run()
                      Each dict must have keys:
                        alert, enrichment, suppression, scoring

        Returns:
            {
                "noisy_rules": [...],
                "suppression_candidates": [...],
                "whitelist_suggestions": [...],
                "severity_miscalibrations": [...],
                "frequency_summary": {...},
                "summary_text": str,
            }
        """
        if not results:
            return self._empty()

        rule_fire_counts: Counter = Counter()
        rule_suppress_counts: Counter = Counter()
        rule_scores: dict[str, list[int]] = {}
        rule_severities: dict[str, list[str]] = {}
        ip_freq: Counter = Counter()
        domain_freq: Counter = Counter()
        user_freq: Counter = Counter()

        for r in results:
            alert = r.get("alert", {})
            scoring = r.get("scoring", {})
            suppression = r.get("suppression", {})
            indicators = alert.get("indicators", {})

            rule_key = alert.get("rule_id") or alert.get("title") or "UNKNOWN"
            score = scoring.get("score", 0)
            severity = alert.get("severity", "Unknown")
            suppressed = suppression.get("suppressed", False)

            rule_fire_counts[rule_key] += 1
            if suppressed:
                rule_suppress_counts[rule_key] += 1

            rule_scores.setdefault(rule_key, []).append(score)
            rule_severities.setdefault(rule_key, []).append(severity.lower())

            # Indicator frequency
            all_ips = (
                indicators.get("src_ips", []) +
                indicators.get("dest_ips", []) +
                indicators.get("ips", [])
            )
            for ip in all_ips:
                ip_freq[ip] += 1
            for d in indicators.get("domains", []):
                domain_freq[d] += 1
            for u in indicators.get("usernames", []):
                user_freq[u] += 1

        # ------------------------------------------------------------------
        # 1. Noisy rules
        # ------------------------------------------------------------------
        noisy_rules = []
        for rule, count in rule_fire_counts.most_common():
            if count >= NOISY_RULE_THRESHOLD:
                avg_score = sum(rule_scores.get(rule, [0])) / max(len(rule_scores.get(rule, [1])), 1)
                suppress_ratio = rule_suppress_counts[rule] / count
                noisy_rules.append({
                    "rule_id": rule,
                    "fire_count": count,
                    "suppress_count": rule_suppress_counts[rule],
                    "suppress_ratio": round(suppress_ratio, 2),
                    "avg_score": round(avg_score, 1),
                    "recommendation": self._noisy_recommendation(count, suppress_ratio, avg_score),
                })

        # ------------------------------------------------------------------
        # 2. Suppression / whitelist candidates
        # ------------------------------------------------------------------
        suppression_candidates = []
        whitelist_suggestions = []
        for rule, count in rule_fire_counts.items():
            suppress_ratio = rule_suppress_counts[rule] / count
            if suppress_ratio >= HIGH_SUPPRESS_RATIO and count >= 2:
                suppression_candidates.append({
                    "rule_id": rule,
                    "fire_count": count,
                    "suppress_ratio": round(suppress_ratio, 2),
                    "suggestion": f"Consider adding rule '{rule}' to suppression_rules.json (suppressed {rule_suppress_counts[rule]}/{count} times)",
                })

        # Frequently seen IPs/domains that are never flagged as malicious
        for ip, freq in ip_freq.most_common(10):
            if freq >= 3:
                whitelist_suggestions.append({
                    "type": "ip",
                    "value": ip,
                    "frequency": freq,
                    "suggestion": f"IP {ip} appears in {freq} alerts — verify and whitelist if internal/benign",
                })
        for domain, freq in domain_freq.most_common(5):
            if freq >= 3:
                whitelist_suggestions.append({
                    "type": "domain",
                    "value": domain,
                    "frequency": freq,
                    "suggestion": f"Domain {domain} appears in {freq} alerts — verify and whitelist if trusted",
                })

        # ------------------------------------------------------------------
        # 3. Severity miscalibrations
        # ------------------------------------------------------------------
        severity_miscalibrations = []
        for rule, severities in rule_severities.items():
            avg_score = sum(rule_scores.get(rule, [0])) / max(len(rule_scores.get(rule, [1])), 1)
            most_common_sev = Counter(severities).most_common(1)[0][0]
            if most_common_sev in ("high", "critical") and avg_score < SEVERITY_MISMATCH_SCORE:
                severity_miscalibrations.append({
                    "rule_id": rule,
                    "declared_severity": most_common_sev.capitalize(),
                    "avg_risk_score": round(avg_score, 1),
                    "suggestion": (
                        f"Rule '{rule}' fires as {most_common_sev.upper()} but "
                        f"consistently scores low ({avg_score:.0f}/100). "
                        f"Consider downgrading severity in your SIEM."
                    ),
                })
            elif most_common_sev in ("low", "info") and avg_score > 60:
                severity_miscalibrations.append({
                    "rule_id": rule,
                    "declared_severity": most_common_sev.capitalize(),
                    "avg_risk_score": round(avg_score, 1),
                    "suggestion": (
                        f"Rule '{rule}' fires as {most_common_sev.upper()} but "
                        f"scores high ({avg_score:.0f}/100). "
                        f"Consider upgrading severity in your SIEM."
                    ),
                })

        # ------------------------------------------------------------------
        # 4. Summary text
        # ------------------------------------------------------------------
        total = len(results)
        suppressed_count = sum(1 for r in results if r.get("suppression", {}).get("suppressed"))
        escalate_count = sum(1 for r in results if r.get("scoring", {}).get("decision") == "ESCALATE")
        investigate_count = sum(1 for r in results if r.get("scoring", {}).get("decision") == "INVESTIGATE")
        noise_ratio = suppressed_count / total if total else 0

        summary_lines = [
            f"Processed {total} alert(s): {escalate_count} ESCALATE, {investigate_count} INVESTIGATE, {suppressed_count} SUPPRESS.",
            f"Noise ratio: {noise_ratio:.0%} of alerts were suppressed.",
        ]
        if noisy_rules:
            top = noisy_rules[0]
            summary_lines.append(
                f"Noisiest rule: '{top['rule_id']}' fired {top['fire_count']} time(s) "
                f"(avg score {top['avg_score']})."
            )
        if severity_miscalibrations:
            summary_lines.append(
                f"{len(severity_miscalibrations)} severity miscalibration(s) detected — "
                f"review your SIEM rule tuning."
            )
        if whitelist_suggestions:
            summary_lines.append(
                f"{len(whitelist_suggestions)} indicator(s) appear frequently — "
                f"consider whitelisting after verification."
            )

        return {
            "noisy_rules": noisy_rules,
            "suppression_candidates": suppression_candidates,
            "whitelist_suggestions": whitelist_suggestions,
            "severity_miscalibrations": severity_miscalibrations,
            "frequency_summary": {
                "total_alerts": total,
                "suppressed": suppressed_count,
                "escalate": escalate_count,
                "investigate": investigate_count,
                "noise_ratio": round(noise_ratio, 3),
                "unique_rules": len(rule_fire_counts),
                "top_rules": rule_fire_counts.most_common(5),
            },
            "summary_text": " ".join(summary_lines),
        }

    @staticmethod
    def _noisy_recommendation(count: int, suppress_ratio: float, avg_score: float) -> str:
        if suppress_ratio >= 0.9:
            return "Strong suppression candidate — almost always suppressed. Add to suppression_rules.json."
        elif suppress_ratio >= 0.6:
            return "Frequent suppression. Consider adding a contextual whitelist rule."
        elif avg_score < 25 and count >= 5:
            return "High volume, low risk. Tune alert threshold or add severity downgrade rule."
        elif count >= 10:
            return "Very high frequency. Investigate tuning: scope-limit the rule or increase threshold."
        else:
            return "Monitor — review trigger conditions and refine if noise continues."

    @staticmethod
    def _empty() -> dict:
        return {
            "noisy_rules": [],
            "suppression_candidates": [],
            "whitelist_suggestions": [],
            "severity_miscalibrations": [],
            "frequency_summary": {},
            "summary_text": "No alerts to analyse.",
        }
