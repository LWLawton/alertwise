# AlertWise 🛡️
### SIEM Alert Triage & Noise Reduction Engine

> **Open-source · Pure heuristics · No ML required · Production-ready**

AlertWise is a command-line security tool that ingests raw SIEM alerts (JSON), enriches them with four threat intelligence sources, applies configurable suppression rules, scores each alert's risk, and outputs clear triage recommendations — all in seconds.

Built for **SOC analysts**, **vCISOs**, **detection engineers**, and **security engineers** who are tired of alert fatigue.

---

## 📸 Demo Output

```
   _   _           _   _ _ _ _
  /_\ | |___ _ _ _| |_| | | (_)___ ___
 / _ \| / -_) '_|  _\ __ / | (_-</ -_)
/_/ \_\_\___|_|  \__|_||_|_|_/__/\___|

  SIEM Alert Triage & Noise Reduction Engine  v1.0.0

► Loading alerts from data/sample_alerts.json...
✓ Loaded 10 alert(s)

┌─────────────────────────────────────────────────────────────────────────────────┐
│                               Triage Summary                                    │
├────┬──────────────┬────────────────────────────────────┬──────────┬───────┬─────┤
│  # │ Alert ID     │ Title                              │ Severity │ Score │ Dec │
├────┼──────────────┼────────────────────────────────────┼──────────┼───────┼─────┤
│  1 │ AW-00001     │ Credential Dumping via LSASS...    │ High     │  81   │ ESC │
│  2 │ AW-00002     │ Suspicious Outbound Beacon — C2    │ High     │  74   │ INV │
│  7 │ AW-00007     │ Ransomware-like File Extension...  │ Critical │  98   │ ESC │
│  9 │ AW-00009     │ Scheduled Vulnerability Scan...    │ Low      │   0   │ SUP │
└────┴──────────────┴────────────────────────────────────┴──────────┴───────┴─────┘

🔧 SIEM Tuning Recommendations
╭─────────────────────────────────────────────────────────────╮
│ Processed 10 alert(s): 2 ESCALATE, 4 INVESTIGATE,          │
│ 3 SUPPRESS. Noise ratio: 30%.                               │
│ Noisiest rule: 'AUTH-FAIL-BURST' fired 3× (avg score 18)   │
╰─────────────────────────────────────────────────────────────╯

✓ Done — AlertWise completed in 1.34s
  Reports saved to reports/
```

### HTML Report Preview
The HTML report features:
- Dark-themed professional dashboard
- Per-alert severity-coloured cards with expandable TI results
- Risk score progress bars (green → yellow → red)
- Interactive distribution chart
- Collapsible MITRE ATT&CK details
- SIEM tuning recommendations section
- Print-friendly CSS

---

## 🏗️ Project Structure

```
alertwise/
├── main.py                        # CLI entry point
├── requirements.txt               # Python dependencies
├── pyproject.toml                 # Build & tooling config
├── .env.example                   # API key template (copy to .env)
│
├── alertwise/                     # Core package
│   ├── __init__.py
│   ├── pipeline.py                # Orchestrator — ties all modules together
│   ├── normalizer.py              # Alert schema normalisation & IOC extraction
│   ├── enricher.py                # TI enrichment (VT, AbuseIPDB, Shodan, OTX)
│   ├── suppressor.py              # Configurable suppression/whitelist engine
│   ├── scorer.py                  # Heuristic risk scoring & triage decisions
│   ├── tuner.py                   # SIEM tuning recommendations engine
│   ├── reporter.py                # TXT + HTML report generation
│   └── utils.py                   # Logging setup, banner
│
├── data/
│   ├── sample_alerts.json         # 10 realistic SIEM alert samples
│   ├── suppression_rules.json     # Configurable suppression rules
│   └── decisions.json             # Analyst override decisions
│
├── cache/                         # TI API response cache (auto-created)
├── reports/                       # Generated reports (auto-created)
│
└── tests/
    ├── __init__.py
    └── test_normalizer.py         # Unit tests (normalizer, suppressor, scorer)
```

---

## ⚙️ Installation

**Requirements:** Python 3.10+

```bash
# 1. Clone the repository
git clone https://github.com/yourname/alertwise.git
cd alertwise

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys (optional — skip for offline demo)
cp .env.example .env
# Edit .env and add your API keys
```

---

## 🔑 API Keys (Optional)

AlertWise works without API keys in `--no-enrich` mode. For full enrichment, add keys to `.env`:

| Provider | Environment Variable | Free Tier | Get Key |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 500 lookups/day | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| Shodan | `SHODAN_API_KEY` | Limited free | [shodan.io](https://account.shodan.io/) |
| AlienVault OTX | `OTX_API_KEY` | Free | [otx.alienvault.com](https://otx.alienvault.com/api) |

TI results are **cached** in `cache/` as JSON files to avoid repeated API calls.

---

## 🚀 Usage

### Basic Usage
```bash
# Full pipeline with TI enrichment
python main.py --input data/sample_alerts.json

# Offline / demo mode (no API calls)
python main.py --input data/sample_alerts.json --no-enrich

# Custom output directory
python main.py --input data/sample_alerts.json --output-dir /tmp/triage/

# Skip HTML report generation
python main.py --input data/sample_alerts.json --no-html

# Verbose debug logging
python main.py --input data/sample_alerts.json --log-level DEBUG
```

### Custom Rules & Overrides
```bash
# Use custom suppression rules
python main.py --input alerts.json --rules /path/to/my_rules.json

# Use custom analyst decisions
python main.py --input alerts.json --decisions /path/to/my_decisions.json
```

### Input Format
AlertWise accepts **a single alert object** or **a list of alerts**:

```json
[
  {
    "event_type": "Alert",
    "metadata": {
      "alert_id": "CORP-12345",
      "timestamp": "2024-06-15T14:32:11Z",
      "source_product": "CrowdStrike Falcon",
      "rule_id": "CRED-ACCESS-001",
      "severity": "High"
    },
    "alert_summary": {
      "title": "Credential Dumping via LSASS Memory Access",
      "description": "mimikatz.exe accessed LSASS memory on WKSTN-042",
      "severity": "High"
    },
    "entities": [
      { "type": "host",    "hostname": "WKSTN-042", "ip": "192.168.10.42" },
      { "type": "user",    "username": "jsmith" },
      { "type": "process", "name": "mimikatz.exe",  "pid": 4821 },
      { "type": "ip",      "value": "185.220.101.47", "direction": "dst" }
    ],
    "mitre_attack": {
      "tactic":       "Credential Access",
      "technique_id": "T1003.001",
      "technique":    "OS Credential Dumping: LSASS Memory"
    }
  }
]
```

**Supported entity types:** `host`, `ip`, `user`, `process`, `file`, `hash`, `domain`, `url`

---

## 🧠 Scoring Model

AlertWise uses a transparent, heuristic scoring model (0–100):

| Component | Max Points | Description |
|---|---|---|
| Base Severity | 35 | Critical=35, High=28, Medium=18, Low=8, Info=3 |
| TI Enrichment | 40 | Scaled from max indicator score across all providers |
| MITRE ATT&CK | 10 | High-impact technique/tactic bonus |
| Context Factors | 15 | Suspicious processes, external IPs, entity spread |
| Internal IP Penalty | -10 | All-internal RFC1918 traffic reduces score |

### Triage Decisions

| Decision | Score Range | Meaning |
|---|---|---|
| 🔴 **ESCALATE** | ≥ 55 | Requires immediate analyst attention |
| 🟠 **INVESTIGATE** | 40–54 | Schedule investigation in current shift |
| 🔵 **MONITOR** | 20–39 | Low priority — add to watch list |
| ⚫ **SUPPRESS** | — | Matched suppression rule or analyst override |
| 🟢 **BENIGN** | < 20 | No action required |

---

## 🔕 Suppression Rules

Edit `data/suppression_rules.json` to customise your suppression logic. Supported rule types:

```json
[
  {
    "name": "internal-scanners",
    "description": "Suppress known scanner IPs",
    "type": "ip_whitelist",
    "enabled": true,
    "values": ["10.10.1.25", "10.10.1.26"]
  },
  {
    "name": "internal-subnet",
    "type": "ip_range",
    "enabled": true,
    "ranges": ["10.0.0.0/8"]
  },
  {
    "name": "trusted-domains",
    "type": "domain_whitelist",
    "enabled": true,
    "values": ["microsoft.com", "windows.com"]
  },
  {
    "name": "info-level-noise",
    "type": "severity_threshold",
    "enabled": true,
    "max_severity": "info"
  },
  {
    "name": "noisy-rule-id",
    "type": "rule_id",
    "enabled": true,
    "values": ["VULN-SCAN-COMPLETE"]
  },
  {
    "name": "high-frequency-rule",
    "type": "frequency_threshold",
    "enabled": true,
    "max_count": 5
  },
  {
    "name": "scanner-accounts",
    "type": "user_whitelist",
    "enabled": true,
    "values": ["svc_nessus", "svc_qualys"]
  },
  {
    "name": "safe-processes",
    "type": "process_whitelist",
    "enabled": true,
    "values": ["veeam_agent.exe", "backup_service.exe"]
  },
  {
    "name": "patch-noise",
    "type": "title_regex",
    "enabled": true,
    "patterns": ["(?i)WSUS.*update", "(?i)SCCM.*deploy"]
  }
]
```

### Analyst Overrides

Edit `data/decisions.json` to override triage decisions by `alert_id` or `rule_id`:

```json
{
  "AW-00009": {
    "action": "suppress",
    "reason": "Confirmed scheduled scan — VM team notified",
    "analyst": "alice@corp.com",
    "reviewed_at": "2024-06-15T17:30:00Z"
  }
}
```

Actions: `escalate` | `investigate` | `suppress` | `benign`

---

## 🔧 SIEM Tuning Recommendations

AlertWise automatically analyses your alert batch and surfaces:

- **Noisy rules** — rules firing ≥3 times with recommendations (suppress, tune threshold, refine scope)
- **Suppression candidates** — rules suppressed ≥70% of the time → candidates for permanent whitelisting
- **Severity miscalibrations** — High/Critical rules scoring consistently low → downgrade in your SIEM
- **Whitelist suggestions** — IPs/domains appearing in 3+ alerts that may warrant permanent whitelisting

These insights directly translate to SIEM tuning tickets and help reduce analyst burnout.

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Expected output:
```
tests/test_normalizer.py::TestNormalizeSeverity::test_high PASSED
tests/test_normalizer.py::TestNormalizeSeverity::test_case_insensitive PASSED
...
tests/test_normalizer.py::TestAlertScorer::test_suppressed_alert_decision PASSED
======================== 22 passed in 0.31s ========================
```

---

## 🏢 Real-World Use Cases

### As a SOC Analyst
- Drop your SIEM export JSON into AlertWise before shift handover
- Get a prioritised triage queue in seconds
- HTML report is ready to share with your team lead

### As a Detection Engineer
- Run AlertWise on a week of alerts to identify your noisiest rules
- Use the tuning recommendations to reduce false positives
- Track suppression ratios over time to measure improvement

### As a vCISO / Consultant
- Import client SIEM exports and generate professional HTML triage reports
- Use SIEM tuning section as talking points in security reviews
- Demonstrate measurable noise reduction to clients

### In Interviews
- Demonstrates end-to-end understanding of the SOC alert lifecycle
- Shows ability to build production-ready Python tooling
- Covers TI integration, heuristic scoring, and reporting — all key SOC skills
- Extensible architecture shows engineering maturity

---

## 🔌 Extending AlertWise

### Adding a New TI Provider

1. Add your lookup function to `alertwise/enricher.py`:
```python
def _my_provider_lookup(indicator: str) -> dict:
    cached = _load_cache("myprovider", indicator)
    if cached:
        return cached
    # ... call API ...
    result = { "provider": "myprovider", "score": ..., "tags": [...], "raw": {} }
    _save_cache("myprovider", indicator, result)
    return result
```

2. Call it in `ThreatEnricher.enrich()` under the appropriate indicator section.

### Adding a New Suppression Rule Type

1. Add a new `elif rtype == "my_type":` block in `SuppressionEngine.evaluate()` in `alertwise/suppressor.py`
2. Add a sample rule to `data/suppression_rules.json`

### Adding New Scoring Factors

Edit `AlertScorer.score()` in `alertwise/scorer.py` — the breakdown dict and reasoning list are transparent and easy to extend.

---

## 📄 Output Files

| File | Description |
|---|---|
| `reports/alertwise_report_YYYYMMDD_HHMMSS.txt` | Full plain-text triage report |
| `reports/alertwise_report_YYYYMMDD_HHMMSS.html` | Professional HTML dashboard report |
| `cache/<provider>_<hash>.json` | Cached TI API responses |

---

## 🔒 Security & Privacy

- **No data leaves your machine** unless you have API keys configured
- API responses are cached locally — indicators are only sent to TI providers once
- Cache files contain raw API responses — treat them as sensitive if indicators are confidential
- `.env` is in `.gitignore` — never commit your API keys

---

## 📜 License

MIT License — free to use, modify, and distribute. Attribution appreciated.

---

## 🤝 Contributing

Pull requests welcome. Priority areas:
- Additional TI provider integrations (GreyNoise, IPInfo, Recorded Future)
- STIX/TAXII alert ingestion support
- Sigma rule mapping
- Slack/Teams/PagerDuty webhook notifications
- Elasticsearch/OpenSearch direct ingestion

---

*Built with ❤️ for the security community. AlertWise is a demonstration project — always validate findings manually before taking production action.*
