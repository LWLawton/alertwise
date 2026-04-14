"""
alertwise/pipeline.py
======================
AlertWise main pipeline orchestrator.

Ties together: normalizer → enricher → suppressor → scorer → tuner → reporter
Produces rich CLI output and writes reports to disk.
"""

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich import box

from alertwise.normalizer import normalize_alert
from alertwise.enricher import ThreatEnricher
from alertwise.suppressor import SuppressionEngine
from alertwise.scorer import AlertScorer
from alertwise.tuner import SIEMTuner
from alertwise.reporter import generate_txt_report, generate_html_report

logger = logging.getLogger(__name__)
console = Console()

# CLI display colours for decisions
DECISION_STYLE = {
    "ESCALATE":    "bold red",
    "INVESTIGATE": "bold yellow",
    "MONITOR":     "bold cyan",
    "SUPPRESS":    "dim",
    "BENIGN":      "bold green",
}

SEVERITY_STYLE = {
    "Critical": "bold red",
    "High":     "red",
    "Medium":   "yellow",
    "Low":      "green",
    "Info":     "cyan",
    "Unknown":  "dim",
}


class AlertWisePipeline:
    """
    Full triage pipeline for a list of alerts.

    Parameters:
        suppression_rules_path – path to suppression_rules.json
        decisions_path         – path to analyst decisions/overrides
        enrich                 – whether to call external TI APIs
        output_dir             – directory for report files
    """

    def __init__(
        self,
        suppression_rules_path: str = "data/suppression_rules.json",
        decisions_path: str = "data/decisions.json",
        enrich: bool = True,
        output_dir: str = "reports",
    ) -> None:
        self.enricher = ThreatEnricher(enabled=enrich)
        self.suppressor = SuppressionEngine(
            rules_path=suppression_rules_path,
            decisions_path=decisions_path,
        )
        self.scorer = AlertScorer()
        self.tuner = SIEMTuner()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, raw_alerts: list[dict]) -> list[dict[str, Any]]:
        """
        Process a list of raw alert dicts through the full pipeline.

        Returns:
            List of result dicts, one per alert, each containing:
                alert, enrichment, suppression, scoring
        """
        results: list[dict] = []

        console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print("[bold cyan]  AlertWise Pipeline Starting[/]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Processing alerts...", total=len(raw_alerts))

            for raw in raw_alerts:
                # 1. Normalise
                alert = normalize_alert(raw)
                alert_id = alert["alert_id"]
                title = alert["title"]

                progress.update(task, description=f"[cyan]Normalising[/] {alert_id}: {title[:40]}...")

                # 2. Register for frequency tracking
                self.suppressor.record_alert(alert)

                # 3. Enrich
                progress.update(task, description=f"[yellow]Enriching[/]  {alert_id}: {title[:40]}...")
                enrichment = self.enricher.enrich(alert)

                # 4. Suppression
                progress.update(task, description=f"[blue]Suppressing[/] {alert_id}: {title[:40]}...")
                suppression = self.suppressor.evaluate(alert)

                # 5. Score
                scoring = self.scorer.score(alert, enrichment, suppression)

                results.append({
                    "alert": alert,
                    "enrichment": enrichment,
                    "suppression": suppression,
                    "scoring": scoring,
                })

                progress.advance(task)

        # 6. Print rich CLI summary
        self._print_summary_table(results)
        self._print_alert_details(results)

        # 7. Tuning analysis
        tuning = self.tuner.analyze(results)
        self._print_tuning_summary(tuning)

        # Attach tuning to pipeline for report methods
        self._last_tuning = tuning

        return results

    # ------------------------------------------------------------------
    # CLI output helpers
    # ------------------------------------------------------------------

    def _print_summary_table(self, results: list[dict]) -> None:
        table = Table(
            title="[bold]Triage Summary[/]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Alert ID", style="cyan", width=16)
        table.add_column("Title", width=36)
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Decision", width=13)
        table.add_column("Confidence", width=10)
        table.add_column("TI Indicators", width=14)

        for i, r in enumerate(results, 1):
            alert = r["alert"]
            scoring = r["scoring"]
            enrichment = r["enrichment"]

            severity = alert.get("severity", "Unknown")
            decision = scoring.get("decision", "?")
            score = scoring.get("score", 0)
            confidence = scoring.get("confidence", "?")
            ti_count = enrichment.get("indicator_count", 0)

            # Score colour
            score_style = "bold green" if score < 30 else "bold yellow" if score < 60 else "bold red"

            table.add_row(
                str(i),
                alert.get("alert_id", "N/A"),
                Text(alert.get("title", "")[:35], overflow="ellipsis"),
                Text(severity, style=SEVERITY_STYLE.get(severity, "")),
                Text(str(score), style=score_style),
                Text(decision, style=DECISION_STYLE.get(decision, "")),
                confidence,
                str(ti_count) if enrichment.get("enabled") else "[dim]disabled[/]",
            )

        console.print(table)

    def _print_alert_details(self, results: list[dict]) -> None:
        console.print("\n[bold cyan]── Detailed Triage Decisions ──────────────────────────────────────[/]\n")

        for i, r in enumerate(results, 1):
            alert = r["alert"]
            scoring = r["scoring"]
            suppression = r["suppression"]
            enrichment = r["enrichment"]

            decision = scoring.get("decision", "?")
            score = scoring.get("score", 0)
            decision_style = DECISION_STYLE.get(decision, "white")

            # Decision emoji
            emoji = {
                "ESCALATE": "🔴",
                "INVESTIGATE": "🟠",
                "MONITOR": "🔵",
                "SUPPRESS": "⚫",
                "BENIGN": "🟢",
            }.get(decision, "⚪")

            title_text = Text()
            title_text.append(f"{emoji} [{i}] ", style="dim")
            title_text.append(alert.get("title", "Untitled"), style="bold white")
            title_text.append(f"  {decision}", style=decision_style)
            title_text.append(f"  ({score}/100)", style="dim")

            console.print(title_text)

            # Reasoning (first 3 lines)
            for reason in scoring.get("reasoning", [])[:3]:
                console.print(f"    [dim]•[/] {reason}")

            if suppression.get("suppressed"):
                console.print(f"    [dim]⛔ {suppression.get('reason', '')}[/]")

            # TI hit summary
            ti_results = enrichment.get("results", {})
            for key, ti_list in list(ti_results.items())[:2]:
                for tr in ti_list:
                    if tr.get("score", 0) > 30 and "error" not in tr:
                        console.print(
                            f"    [yellow]⚠ TI:[/] [{tr['provider'].upper()}] {key} "
                            f"→ score={tr['score']}, tags={tr.get('tags', [])}"
                        )

            console.print()

    def _print_tuning_summary(self, tuning: dict) -> None:
        freq = tuning.get("frequency_summary", {})
        noise_ratio = freq.get("noise_ratio", 0)

        lines = [tuning.get("summary_text", "")]

        noisy = tuning.get("noisy_rules", [])
        if noisy:
            lines.append(f"\n[bold]Noisy Rules:[/]")
            for nr in noisy[:5]:
                lines.append(
                    f"  [yellow]•[/] [bold]{nr['rule_id']}[/] — fired {nr['fire_count']}×, "
                    f"avg score {nr['avg_score']} → {nr['recommendation']}"
                )

        mismatches = tuning.get("severity_miscalibrations", [])
        if mismatches:
            lines.append(f"\n[bold]Severity Miscalibrations:[/]")
            for sm in mismatches[:3]:
                lines.append(f"  [red]•[/] {sm['suggestion']}")

        panel_content = "\n".join(lines)
        console.print(
            Panel(
                panel_content,
                title="[bold cyan]🔧 SIEM Tuning Recommendations[/]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    # ------------------------------------------------------------------
    # Report writers
    # ------------------------------------------------------------------

    def write_txt_report(self, results: list[dict]) -> str:
        tuning = getattr(self, "_last_tuning", {})
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = str(self.output_dir / f"alertwise_report_{ts}.txt")
        return generate_txt_report(results, tuning, path)

    def write_html_report(self, results: list[dict]) -> str:
        tuning = getattr(self, "_last_tuning", {})
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = str(self.output_dir / f"alertwise_report_{ts}.html")
        return generate_html_report(results, tuning, path)
