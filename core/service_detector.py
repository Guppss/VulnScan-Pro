"""
Service detection and banner grabbing for VulnScan Pro.

Attempts to identify running services by probing banners and sending
protocol-specific requests. Works for common services on well-known ports.
"""
from __future__ import annotations

import re
import socket
from typing import Optional

from utils.logger import logger
from utils.network_utils import PORT_SERVICE_MAP


# Banner patterns to extract product name and version
# Each entry: (regex_pattern, product_name, version_group_index)
BANNER_PATTERNS: list[tuple[str, str, int]] = [
    # SSH
    (r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)", "OpenSSH", 1),
    (r"SSH-[\d.]+-dropbear[_\s]([\d.]+)", "Dropbear SSH", 1),
    # FTP
    (r"vsftpd\s+([\d.]+)", "vsftpd", 1),
    (r"ProFTPD\s+([\d.]+)", "ProFTPD", 1),
    (r"FileZilla Server\s+([\d.]+)", "FileZilla Server", 1),
    (r"Pure-FTPd", "Pure-FTPd", 0),
    (r"wu-ftpd\s+([\d.]+)", "wu-ftpd", 1),
    # SMTP
    (r"Postfix\s+ESMTP", "Postfix", 0),
    (r"Exim\s+([\d.]+)", "Exim", 1),
    (r"Microsoft ESMTP MAIL Service", "Microsoft SMTP", 0),
    (r"Sendmail\s+([\d./]+)", "Sendmail", 1),
    # HTTP Server header patterns
    (r"Apache/([\d.]+)", "Apache", 1),
    (r"nginx/([\d.]+)", "Nginx", 1),
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", 1),
    (r"lighttpd/([\d.]+)", "lighttpd", 1),
    (r"LiteSpeed", "LiteSpeed", 0),
    (r"Caddy", "Caddy", 0),
    # Database
    (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB", 1),
    (r"(\d+\.\d+\.\d+)", "MySQL", 1),  # MySQL sends version as first greeting
    # Redis
    (r"\+PONG", "Redis", 0),
    (r"redis_version:([\d.]+)", "Redis", 1),
]

HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 8081, 3000, 4000, 5000}
HTTPS_PORTS = {443, 8443, 4443}
SSH_PORTS = {22, 2222}
FTP_PORTS = {21, 2121}
SMTP_PORTS = {25, 587, 465, 2525}
MYSQL_PORTS = {3306}
REDIS_PORTS = {6379}


class ServiceDetector:
    """Static service fingerprinting methods."""

    @classmethod
    def detect(cls, host: str, port: int, timeout: float = 3.0) -> dict:
        """
        Detect the service running on host:port.

        Returns a dict with keys: service, product, version, banner.
        """
        result: dict = {
            "service": PORT_SERVICE_MAP.get(port, "unknown"),
            "product": "",
            "version": "",
            "banner": "",
        }

        try:
            if port in HTTP_PORTS:
                cls._probe_http(host, port, timeout, result)
            elif port in SSH_PORTS:
                cls._probe_banner(host, port, timeout, result)
            elif port in FTP_PORTS:
                cls._probe_banner(host, port, timeout, result)
            elif port in SMTP_PORTS:
                cls._probe_banner(host, port, timeout, result)
            elif port in MYSQL_PORTS:
                cls._probe_mysql(host, port, timeout, result)
            elif port in REDIS_PORTS:
                cls._probe_redis(host, port, timeout, result)
            else:
                # Generic banner grab
                cls._probe_banner(host, port, timeout, result)
        except Exception as exc:
            logger.debug("Detection error on %s:%d — %s", host, port, exc)

        return result

    # ── Protocol-specific probers ──────────────────────────────────────────────

    @classmethod
    def _probe_banner(
        cls, host: str, port: int, timeout: float, result: dict
    ) -> None:
        """Grab the initial connect banner and parse product/version."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                try:
                    data = sock.recv(2048)
                    banner = data.decode("utf-8", errors="replace").strip()
                    result["banner"] = banner[:500]
                    cls._parse_banner(banner, result)
                except socket.timeout:
                    pass
        except (ConnectionRefusedError, OSError):
            pass

    @classmethod
    def _probe_http(
        cls, host: str, port: int, timeout: float, result: dict
    ) -> None:
        """Send HTTP HEAD request and extract Server header."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                request = (
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                    f"User-Agent: VulnScanPro/1.0\r\nConnection: close\r\n\r\n"
                ).encode()
                sock.sendall(request)
                raw = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if b"\r\n\r\n" in raw or len(raw) > 8192:
                        break
                response = raw.decode("utf-8", errors="replace")
                result["banner"] = response[:500]
                result["service"] = "http"

                for line in response.splitlines():
                    lower = line.lower()
                    if lower.startswith("server:"):
                        server_val = line.split(":", 1)[1].strip()
                        cls._parse_banner(server_val, result)
                        break
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

    @classmethod
    def _probe_mysql(
        cls, host: str, port: int, timeout: float, result: dict
    ) -> None:
        """Read MySQL initial handshake packet to extract server version."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(256)
                if len(data) > 5:
                    # MySQL handshake: [3-byte length][1-byte seq][payload]
                    # payload starts with protocol version byte then null-term version
                    payload = data[4:]
                    if payload[0] in (10, 9):  # protocol v10 or v9
                        null_idx = payload.find(b"\x00", 1)
                        if null_idx > 1:
                            version_str = payload[1:null_idx].decode("ascii", errors="replace")
                            result["banner"] = f"MySQL {version_str}"
                            result["service"] = "mysql"
                            if "mariadb" in version_str.lower():
                                result["product"] = "MariaDB"
                            else:
                                result["product"] = "MySQL"
                            result["version"] = version_str.split("-")[0]
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

    @classmethod
    def _probe_redis(
        cls, host: str, port: int, timeout: float, result: dict
    ) -> None:
        """Send PING and INFO to Redis to detect version."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                pong = sock.recv(128).decode("ascii", errors="replace")
                if "+PONG" in pong or "PONG" in pong:
                    result["service"] = "redis"
                    result["product"] = "Redis"
                    # Ask for version
                    sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
                    info_raw = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        info_raw += chunk
                        if len(info_raw) > 16384:
                            break
                    info = info_raw.decode("utf-8", errors="replace")
                    m = re.search(r"redis_version:([\d.]+)", info)
                    if m:
                        result["version"] = m.group(1)
                        result["banner"] = f"Redis {result['version']}"
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

    # ── Banner parsing ─────────────────────────────────────────────────────────

    @classmethod
    def _parse_banner(cls, banner: str, result: dict) -> None:
        """Apply pattern matching to extract product name and version."""
        for pattern, product, ver_group in BANNER_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                result["product"] = product
                if ver_group > 0:
                    try:
                        result["version"] = m.group(ver_group)
                    except IndexError:
                        pass
                return
