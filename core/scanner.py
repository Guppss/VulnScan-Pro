"""
Multithreaded TCP port scanner with real-time progress reporting.

All heavy work runs inside a QThread so the GUI stays responsive.
The scanner uses a ThreadPoolExecutor internally for parallel port probing.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List

from PyQt6.QtCore import QThread, pyqtSignal

from utils.logger import logger
from utils.network_utils import get_service_name, is_port_open


@dataclass
class ScanConfig:
    """All parameters needed to configure a scan run."""
    targets: List[str]
    ports: List[int]
    thread_count: int = 150
    timeout: float = 1.0
    detect_services: bool = True
    service_timeout: float = 3.0
    scan_name: str = ""


@dataclass
class PortResult:
    """Result for a single host:port probe."""
    host: str
    port: int
    status: str          # 'open' | 'closed' | 'filtered'
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "scan_time": self.scan_time,
        }


class PortScanWorker(QThread):
    """
    Background QThread that drives a full port scan.

    Signals
    -------
    progress_updated(completed, total)
        Emitted after every probed port.
    port_found(result_dict)
        Emitted for every port whose status is 'open'.
    host_started(ip)
        Emitted when scanning begins on a new host.
    host_finished(ip, open_count)
        Emitted when all ports on a host are scanned.
    scan_finished(all_open_results)
        Emitted once when the entire scan is done.
    log_message(text)
        Human-readable log line for the scan console.
    error_occurred(message)
        Emitted on unrecoverable errors.
    """

    progress_updated = pyqtSignal(int, int)
    port_found = pyqtSignal(dict)
    host_started = pyqtSignal(str)
    host_finished = pyqtSignal(str, int)
    scan_finished = pyqtSignal(list)
    log_message = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, config: ScanConfig, parent=None) -> None:
        super().__init__(parent)
        self.config = config
        self._stop_requested = False
        self._open_results: list[dict] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def stop(self) -> None:
        """Request a graceful stop; the thread will finish the current batch."""
        self._stop_requested = True

    # ── QThread entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        self._open_results.clear()
        total_tasks = len(self.config.targets) * len(self.config.ports)
        completed = 0

        self.log_message.emit(
            f"[*] Starting scan — {len(self.config.targets)} host(s) × "
            f"{len(self.config.ports)} port(s) = {total_tasks:,} probes | "
            f"{self.config.thread_count} threads | timeout {self.config.timeout}s"
        )

        try:
            for target in self.config.targets:
                if self._stop_requested:
                    break

                self.host_started.emit(target)
                self.log_message.emit(f"[>] Scanning {target} ...")
                host_open = 0

                with ThreadPoolExecutor(max_workers=self.config.thread_count) as pool:
                    future_to_port = {
                        pool.submit(self._probe_port, target, port): port
                        for port in self.config.ports
                    }
                    for future in as_completed(future_to_port):
                        if self._stop_requested:
                            pool.shutdown(wait=False, cancel_futures=True)
                            break
                        try:
                            result = future.result()
                            completed += 1
                            self.progress_updated.emit(completed, total_tasks)
                            if result["status"] == "open":
                                host_open += 1
                                self._open_results.append(result)
                                self.port_found.emit(result)
                                ver_str = (
                                    f" ({result['product']} {result['version']})"
                                    if result.get("product")
                                    else ""
                                )
                                self.log_message.emit(
                                    f"    [+] {target}:{result['port']}/tcp  "
                                    f"OPEN  {result['service']}{ver_str}"
                                )
                        except Exception as exc:
                            logger.debug("Future error: %s", exc)
                            completed += 1
                            self.progress_updated.emit(completed, total_tasks)

                self.host_finished.emit(target, host_open)

        except Exception as exc:
            logger.exception("Fatal scan error")
            self.error_occurred.emit(str(exc))

        if self._stop_requested:
            self.log_message.emit("[!] Scan stopped by user.")
        else:
            self.log_message.emit(
                f"[✓] Scan complete — {len(self._open_results)} open port(s) found."
            )

        self.scan_finished.emit(self._open_results)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _probe_port(self, host: str, port: int) -> dict:
        """Probe a single port; optionally enrich with service info."""
        t0 = time.monotonic()
        status = is_port_open(host, port, self.config.timeout)
        elapsed = round(time.monotonic() - t0, 4)

        result = PortResult(
            host=host,
            port=port,
            status=status,
            service=get_service_name(port),
            scan_time=elapsed,
        )

        if status == "open" and self.config.detect_services:
            self._enrich_service(result)

        return result.to_dict()

    def _enrich_service(self, result: PortResult) -> None:
        """Attempt banner grab and service fingerprinting on an open port."""
        from core.service_detector import ServiceDetector
        try:
            info = ServiceDetector.detect(
                result.host, result.port, self.config.service_timeout
            )
            result.banner = info.get("banner", "")
            result.product = info.get("product", "")
            result.version = info.get("version", "")
            if info.get("service"):
                result.service = info["service"]
        except Exception as exc:
            logger.debug(
                "Service detection failed %s:%d — %s", result.host, result.port, exc
            )
