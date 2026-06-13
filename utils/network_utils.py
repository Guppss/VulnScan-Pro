"""Network utility functions for VulnScan Pro."""
from __future__ import annotations

import socket
from typing import Optional

PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpc",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3306: "mysql",
    3389: "ms-wbt-server", 4444: "backdoor", 5432: "postgresql",
    5900: "vnc", 5901: "vnc-1", 6379: "redis", 6443: "kubernetes",
    8080: "http-alt", 8443: "https-alt", 8888: "http-proxy",
    9200: "elasticsearch", 9300: "elasticsearch-cluster",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb-shard",
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1080, 1433, 1521, 2049, 2375, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017,
]

TOP_1000_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30,
    32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88,
    89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256,
    259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
    425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513,
    514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
    616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691,
    700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800,
    801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912,
    981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009,
    1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
    1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
    1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062,
    1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
    1074, 1075, 1076, 1077, 1078, 1079, 1080, 1110, 1234, 1433, 1434,
    1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2375, 2376,
    3000, 3306, 3389, 4000, 4444, 4848, 5000, 5432, 5900, 6000, 6379,
    7000, 7001, 7002, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018, 50000,
]

WELL_KNOWN_PORTS = list(range(1, 1024))


def get_service_name(port: int) -> str:
    """Return a human-readable service name for the given port number."""
    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def is_port_open(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt a TCP connection to host:port.

    Returns 'open', 'closed', or 'filtered'.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, OSError):
        return "filtered"


def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt to grab the initial banner sent by a service on connect.

    Returns the banner string or None.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(2048)
                if data:
                    return data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, UnicodeDecodeError):
                pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def grab_http_banner(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """
    Send an HTTP HEAD request and return the raw response headers.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ).encode()
            sock.sendall(request)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
            return response.decode("utf-8", errors="replace")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
