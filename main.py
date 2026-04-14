#!/usr/bin/env python3
"""
AlertWise — SIEM Alert Triage & Noise Reduction Engine
========================================================
Entry point: parses CLI arguments and orchestrates the full pipeline.

Usage:
    python main.py --input data/sample_alerts.json
    python main.py --input data/sample_alerts.json --no-enrich
    python main.py --input data/sample_alerts.json --output-dir reports/
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from alertwise.pipeline import AlertWisePipeline
from alertwise.utils import setup_logging, banner

console = Console()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="alertwise",
        description="AlertWise — SIEM Alert Triage & Noise Reduction Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --input data/sample_alerts.json
  python main.py --input data/sample_alerts.json --no-enrich
  python main.py --input data/sample_alerts.json --output-dir reports/ --log-level DEBUG
        """,
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to JSON file containing alert(s)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Directory to write reports (default: reports/)",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        default=False,
        help="Skip threat intelligence enrichment (useful for offline/demo mode)",
    )
    parser.add_argument(
        "--rules",
        default="data/suppression_rules.json",
        help="Path to suppression rules JSON (default: data/suppression_rules.json)",
    )
    parser.add_argument(
        "--decisions",
        default="data/decisions.json",
        help="Path to analyst decision overrides JSON (default: data/decisions.json)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        default=False,
        help="Skip HTML report generation",
    )
    parser.add_argument(
        "--no-txt",
        action="store_true",
        default=False,
        help="Skip TXT report generation",
    )
    return parser.parse_args()


def load_alerts(input_path: str) -> list[dict]:
    """
    Load alerts from a JSON file.
    Supports both a single alert object and a list of alerts.
    """
    path = Path(input_path)
    if not path.exists():
        console.print(f"[bold red]ERROR:[/] Input file not found: {input_path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ERROR:[/] Failed to parse JSON: {e}")
        sys.exit(1)

    # Accept single alert or list
    if isinstance(data, dict):
        return [data]
    elif isinstance(data, list):
        return data
    else:
        console.print("[bold red]ERROR:[/] Input must be a JSON object or array of objects.")
        sys.exit(1)


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Print banner
    banner(console)

    start_time = time.time()

    # Load alerts
    console.print(f"\n[cyan]►[/] Loading alerts from [bold]{args.input}[/]...")
    alerts = load_alerts(args.input)
    console.print(f"[green]✓[/] Loaded [bold]{len(alerts)}[/] alert(s)\n")

    # Build output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run pipeline
    pipeline = AlertWisePipeline(
        suppression_rules_path=args.rules,
        decisions_path=args.decisions,
        enrich=not args.no_enrich,
        output_dir=str(output_dir),
    )

    results = pipeline.run(alerts)

    # Generate reports
    if not args.no_txt:
        pipeline.write_txt_report(results)

    if not args.no_html:
        pipeline.write_html_report(results)

    elapsed = time.time() - start_time
    console.print(
        Panel(
            f"[bold green]AlertWise completed in {elapsed:.2f}s[/]\n"
            f"Processed [bold]{len(results)}[/] alert(s) · "
            f"Reports saved to [bold]{output_dir}/[/]",
            title="[bold cyan]✓ Done[/]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
