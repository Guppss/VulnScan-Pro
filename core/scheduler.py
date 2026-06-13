"""
Scan scheduler for VulnScan Pro.

Allows recurring scans to be configured and executed automatically
using a background QTimer-based loop.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, List, Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from utils.logger import logger

SCHEDULE_FILE = Path(__file__).resolve().parent.parent / "schedules.json"


@dataclass
class ScheduledScan:
    """Configuration for a single scheduled scan job."""
    job_id: str
    name: str
    target: str
    port_preset: str
    interval_hours: int
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "target": self.target,
            "port_preset": self.port_preset,
            "interval_hours": self.interval_hours,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
        }

    @staticmethod
    def from_dict(data: dict) -> "ScheduledScan":
        return ScheduledScan(**data)


class ScanScheduler(QObject):
    """
    Manages scheduled scan jobs, persisting them to a JSON file
    and triggering them via a QTimer.
    """

    scan_due = pyqtSignal(object)  # emits ScheduledScan when it is time to run

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._jobs: list[ScheduledScan] = []
        self._timer = QTimer(self)
        self._timer.setInterval(60_000)  # check every minute
        self._timer.timeout.connect(self._check_jobs)
        self._load()

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the scheduler timer."""
        self._timer.start()
        logger.info("Scan scheduler started (%d jobs loaded).", len(self._jobs))

    def stop(self) -> None:
        """Stop the scheduler timer."""
        self._timer.stop()

    def add_job(self, job: ScheduledScan) -> None:
        """Add a new scheduled job and save."""
        job.next_run = self._next_run_time(job.interval_hours)
        self._jobs.append(job)
        self._save()
        logger.info("Scheduled scan '%s' added (every %dh).", job.name, job.interval_hours)

    def remove_job(self, job_id: str) -> None:
        """Remove a job by ID and save."""
        self._jobs = [j for j in self._jobs if j.job_id != job_id]
        self._save()

    def update_job(self, updated: ScheduledScan) -> None:
        """Replace a job record by ID and save."""
        self._jobs = [updated if j.job_id == updated.job_id else j for j in self._jobs]
        self._save()

    def get_jobs(self) -> list[ScheduledScan]:
        return list(self._jobs)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _check_jobs(self) -> None:
        now = datetime.now()
        changed = False
        for job in self._jobs:
            if not job.enabled or not job.next_run:
                continue
            due = datetime.fromisoformat(job.next_run)
            if now >= due:
                logger.info("Scheduled scan '%s' is due — triggering.", job.name)
                job.last_run = now.isoformat()
                job.next_run = self._next_run_time(job.interval_hours)
                self.scan_due.emit(job)
                changed = True
        if changed:
            self._save()

    @staticmethod
    def _next_run_time(interval_hours: int) -> str:
        return (datetime.now() + timedelta(hours=interval_hours)).isoformat()

    def _save(self) -> None:
        try:
            SCHEDULE_FILE.write_text(
                json.dumps([j.to_dict() for j in self._jobs], indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.error("Failed to save schedules: %s", exc)

    def _load(self) -> None:
        if not SCHEDULE_FILE.exists():
            return
        try:
            data = json.loads(SCHEDULE_FILE.read_text(encoding="utf-8"))
            self._jobs = [ScheduledScan.from_dict(d) for d in data]
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.error("Failed to load schedules: %s", exc)
