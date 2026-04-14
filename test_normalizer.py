"""
tests/test_normalizer.py
=========================
Unit tests for the alert normaliser.
"""

import pytest
from alertwise.normalizer import (
    normalize_alert,
    normalize_severity,
    parse_entities,
    extract_indicators_from_text,
)


# ---------------------------------------------------------------------------
# normalize_severity
# ---------------------------------------------------------------------------

class TestNormalizeSeverity:
    def test_high(self):
        assert normalize_severity("High") == "High"

    def test_case_insensitive(self):
        assert normalize_severity("HIGH") == "High"
        assert normalize_severity("high") == "High"

    def test_medium_aliases(self):
        assert normalize_severity("Medium") == "Medium"
        assert normalize_severity("med") == "Medium"

    def test_info_aliases(self):
        assert normalize_severity("info") == "Info"
        assert normalize_severity("Informational") == "Info"

    def test_none_returns_unknown(self):
        assert normalize_severity(None) == "Unknown"

    def test_empty_returns_unknown(self):
        assert normalize_severity("") == "Unknown"

    def test_critical(self):
        assert normalize_severity("critical") == "Critical"


# ---------------------------------------------------------------------------
# extract_indicators_from_text
# ---------------------------------------------------------------------------

class TestExtractIndicators:
    def test_ip_extraction(self):
        text = "Connection from 192.168.1.100 to 8.8.8.8"
        result = extract_indicators_from_text(text)
        assert "192.168.1.100" in result["ips"]
        assert "8.8.8.8" in result["ips"]

    def test_sha256_extraction(self):
        # Exactly 64 hex characters required for SHA-256
        h = "7c5d9a1f3b8e2c6d4f0a9b7e5c3d1f8a2e4b6c0d9f7a5e3b1c8d6f4a2e0b8c66"
        assert len(h) == 64, f"Test hash must be 64 chars, got {len(h)}"
        text = f"File hash: {h}"
        result = extract_indicators_from_text(text)
        assert h in result["sha256"]

    def test_url_extraction(self):
        text = "Beacon to https://malicious.example.com/path?q=1"
        result = extract_indicators_from_text(text)
        assert any("malicious.example.com" in u for u in result["urls"])

    def test_no_indicators(self):
        result = extract_indicators_from_text("Normal log message with no indicators")
        assert result["ips"] == []
        assert result["urls"] == []


# ---------------------------------------------------------------------------
# parse_entities
# ---------------------------------------------------------------------------

class TestParseEntities:
    def test_ip_entity_directional(self):
        entities = [
            {"type": "ip", "value": "10.0.0.1", "direction": "src"},
            {"type": "ip", "value": "8.8.8.8",  "direction": "dst"},
        ]
        result = parse_entities(entities)
        assert "10.0.0.1" in result["src_ips"]
        assert "8.8.8.8" in result["dest_ips"]

    def test_host_entity(self):
        entities = [{"type": "host", "hostname": "DC-01", "ip": "192.168.1.1"}]
        result = parse_entities(entities)
        assert "DC-01" in result["hostnames"]
        assert "192.168.1.1" in result["ips"]

    def test_user_entity(self):
        entities = [{"type": "user", "username": "jsmith"}]
        result = parse_entities(entities)
        assert "jsmith" in result["usernames"]

    def test_hash_entity(self):
        entities = [{"type": "hash", "value": "abc123def456" * 2}]
        result = parse_entities(entities)
        assert len(result["file_hashes"]) > 0

    def test_process_entity(self):
        entities = [{"type": "process", "name": "mimikatz.exe"}]
        result = parse_entities(entities)
        assert "mimikatz.exe" in result["processes"]

    def test_empty_entities(self):
        result = parse_entities([])
        assert result["ips"] == []
        assert result["usernames"] == []


# ---------------------------------------------------------------------------
# normalize_alert
# ---------------------------------------------------------------------------

SAMPLE_ALERT = {
    "event_type": "Alert",
    "metadata": {
        "alert_id": "TEST-001",
        "timestamp": "2024-06-15T14:32:11Z",
        "source_product": "CrowdStrike",
        "rule_id": "CRED-001",
        "severity": "High",
    },
    "alert_summary": {
        "title": "LSASS Access Detected",
        "description": "mimikatz accessed LSASS",
        "severity": "High",
    },
    "entities": [
        {"type": "host",    "hostname": "WKSTN-042", "ip": "192.168.10.42"},
        {"type": "process", "name": "mimikatz.exe"},
        {"type": "user",    "username": "jsmith"},
    ],
    "mitre_attack": {
        "tactic": "Credential Access",
        "technique_id": "T1003.001",
    },
}


class TestNormalizeAlert:
    def test_basic_fields(self):
        result = normalize_alert(SAMPLE_ALERT)
        assert result["alert_id"] == "TEST-001"
        assert result["title"] == "LSASS Access Detected"
        assert result["severity"] == "High"
        assert result["source_product"] == "CrowdStrike"
        assert result["rule_id"] == "CRED-001"

    def test_mitre_fields(self):
        result = normalize_alert(SAMPLE_ALERT)
        assert result["mitre_technique"] == "T1003.001"
        assert result["mitre_tactic"] == "Credential Access"

    def test_indicators_populated(self):
        result = normalize_alert(SAMPLE_ALERT)
        indicators = result["indicators"]
        assert "WKSTN-042" in indicators["hostnames"]
        assert "mimikatz.exe" in indicators["processes"]
        assert "jsmith" in indicators["usernames"]

    def test_raw_preserved(self):
        result = normalize_alert(SAMPLE_ALERT)
        assert result["raw"] == SAMPLE_ALERT

    def test_missing_metadata(self):
        """Alert without metadata block should still normalise cleanly."""
        minimal = {
            "alert_summary": {"title": "Test", "severity": "Low"},
            "entities": [],
        }
        result = normalize_alert(minimal)
        assert result["title"] == "Test"
        assert result["severity"] == "Low"
        assert result["alert_id"].startswith("AW-")

    def test_single_alert_not_list(self):
        """normalize_alert handles a single dict, not a list."""
        result = normalize_alert(SAMPLE_ALERT)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Suppressor
# ---------------------------------------------------------------------------

from alertwise.suppressor import SuppressionEngine, _ip_in_range, _severity_rank


class TestIPInRange:
    def test_in_range(self):
        assert _ip_in_range("192.168.1.50", "192.168.1.0/24") is True

    def test_out_of_range(self):
        assert _ip_in_range("10.0.0.1", "192.168.1.0/24") is False

    def test_invalid_ip(self):
        assert _ip_in_range("not-an-ip", "192.168.1.0/24") is False


class TestSeverityRank:
    def test_ordering(self):
        assert _severity_rank("critical") > _severity_rank("high")
        assert _severity_rank("high") > _severity_rank("medium")
        assert _severity_rank("medium") > _severity_rank("low")
        assert _severity_rank("low") > _severity_rank("info")

    def test_case_insensitive(self):
        assert _severity_rank("HIGH") == _severity_rank("high")


class TestSuppressionEngine:
    def _make_engine(self, rules: list) -> SuppressionEngine:
        import json, tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(rules, f)
            rules_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            dec_path = f.name

        return SuppressionEngine(rules_path=rules_path, decisions_path=dec_path)

    def test_ip_whitelist_suppresses(self):
        engine = self._make_engine([{
            "name": "test-whitelist",
            "type": "ip_whitelist",
            "enabled": True,
            "values": ["1.2.3.4"],
        }])
        alert = {"indicators": {"src_ips": ["1.2.3.4"], "dest_ips": [], "ips": []},
                 "title": "Test", "severity": "High", "rule_id": "", "alert_id": "X",
                 "source_product": ""}
        result = engine.evaluate(alert)
        assert result["suppressed"] is True

    def test_severity_threshold_suppresses_info(self):
        engine = self._make_engine([{
            "name": "low-sev",
            "type": "severity_threshold",
            "enabled": True,
            "max_severity": "info",
        }])
        alert = {"indicators": {}, "title": "X", "severity": "Info",
                 "rule_id": "", "alert_id": "Y", "source_product": ""}
        result = engine.evaluate(alert)
        assert result["suppressed"] is True

    def test_severity_threshold_does_not_suppress_medium(self):
        engine = self._make_engine([{
            "name": "low-sev",
            "type": "severity_threshold",
            "enabled": True,
            "max_severity": "info",
        }])
        alert = {"indicators": {}, "title": "X", "severity": "Medium",
                 "rule_id": "", "alert_id": "Z", "source_product": ""}
        result = engine.evaluate(alert)
        assert result["suppressed"] is False


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

from alertwise.scorer import AlertScorer


class TestAlertScorer:
    def _minimal_alert(self, severity: str = "High") -> dict:
        return {
            "alert_id": "TEST",
            "title": "Test",
            "severity": severity,
            "mitre_technique": "",
            "mitre_tactic": "",
            "indicators": {},
            "entities": [],
        }

    def test_high_severity_scores_higher_than_low(self):
        scorer = AlertScorer()
        no_enrich = {"enabled": False, "results": {}, "max_score": 0}
        no_suppress = {"suppressed": False, "matched_rules": []}
        high = scorer.score(self._minimal_alert("High"), no_enrich, no_suppress)
        low  = scorer.score(self._minimal_alert("Low"),  no_enrich, no_suppress)
        assert high["score"] > low["score"]

    def test_suppressed_alert_decision(self):
        scorer = AlertScorer()
        suppress = {"suppressed": True, "matched_rules": ["test-rule"], "reason": "test"}
        result = scorer.score(self._minimal_alert(), {"enabled": False, "results": {}, "max_score": 0}, suppress)
        assert result["decision"] == "SUPPRESS"

    def test_score_in_range(self):
        scorer = AlertScorer()
        no_enrich = {"enabled": False, "results": {}, "max_score": 0}
        no_suppress = {"suppressed": False, "matched_rules": []}
        result = scorer.score(self._minimal_alert("High"), no_enrich, no_suppress)
        assert 0 <= result["score"] <= 100

    def test_critical_scores_higher_than_high(self):
        """Critical severity base score > High severity base score."""
        scorer = AlertScorer()
        no_e = {"enabled": False, "results": {}, "max_score": 0}
        no_s = {"suppressed": False, "matched_rules": []}
        critical = scorer.score(self._minimal_alert("Critical"), no_e, no_s)
        high     = scorer.score(self._minimal_alert("High"),     no_e, no_s)
        assert critical["score"] > high["score"]

    def test_critical_plus_mitre_escalates(self):
        """Critical + high-impact MITRE technique should trigger ESCALATE or INVESTIGATE."""
        scorer = AlertScorer()
        no_e = {"enabled": False, "results": {}, "max_score": 0}
        no_s = {"suppressed": False, "matched_rules": []}
        alert = self._minimal_alert("Critical")
        alert["mitre_technique"] = "T1486"
        alert["mitre_tactic"]    = "Impact"
        result = scorer.score(alert, no_e, no_s)
        assert result["decision"] in ("ESCALATE", "INVESTIGATE")
