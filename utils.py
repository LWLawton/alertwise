"""
alertwise/utils.py
===================
Shared utilities: logging configuration, banner, helpers.
"""

import logging
import sys
from rich.console import Console
from rich.text import Text


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with a clean formatter."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Silence noisy third-party loggers
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def banner(console: Console) -> None:
    """Print the AlertWise ASCII banner."""
    art = r"""
   _   _           _   _ _ _ _
  /_\ | |___ _ _ _| |_| | | (_)___ ___
 / _ \| / -_) '_|  _\ __ / | (_-</ -_)
/_/ \_\_\___|_|  \__|_||_|_|_/__/\___|
"""
    t = Text()
    t.append(art, style="bold cyan")
    console.print(t)
    console.print(
        "  [bold]SIEM Alert Triage & Noise Reduction Engine[/]  "
        "[dim]v1.0.0[/]\n"
        "  [dim]Open source · Pure heuristics · No ML required[/]\n"
    )
