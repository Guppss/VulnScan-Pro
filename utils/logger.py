"""Centralized logging configuration for VulnScan Pro."""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path


def get_log_directory() -> Path:
    """Return application log directory, creating it if necessary."""
    base = Path(__file__).resolve().parent.parent / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def setup_logger(name: str = "vulnscan_pro") -> logging.Logger:
    """Configure and return the application logger."""
    log = logging.getLogger(name)
    if log.handlers:
        return log

    log.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    log_file = get_log_directory() / f"vulnscan_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(fmt)
    file_handler.setFormatter(fmt)

    log.addHandler(console_handler)
    log.addHandler(file_handler)
    return log


logger = setup_logger()
