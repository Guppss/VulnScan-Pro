"""Input validation utilities for VulnScan Pro."""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import List, Tuple


def validate_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Return True if the string is valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """Return True if the string is a syntactically valid hostname."""
    if not hostname or len(hostname) > 253:
        return False
    hostname = hostname.rstrip(".")
    allowed = re.compile(r"^(?!-)[A-Z\d\-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(part) for part in hostname.split("."))


def validate_port_range(port_range: str) -> Tuple[bool, str]:
    """
    Validate a port range string.

    Accepted formats: '80', '1-1024', '80,443,8080', '1-100,443,8080-8090'.
    Returns (is_valid, error_message).
    """
    try:
        ports = parse_port_range(port_range)
        if not ports:
            return False, "Port range produced no ports."
        if any(p < 1 or p > 65535 for p in ports):
            return False, "Ports must be between 1 and 65535."
        return True, ""
    except ValueError as exc:
        return False, str(exc)


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse a port range string into a sorted list of unique port numbers.

    Raises ValueError on invalid input.
    """
    ports: set[int] = set()
    for segment in port_range.replace(" ", "").split(","):
        if not segment:
            continue
        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid range segment: {segment!r}")
            start, end = int(parts[0]), int(parts[1])
            if start > end:
                raise ValueError(f"Start {start} is greater than end {end}.")
            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        else:
            port = int(segment)
            if port < 1 or port > 65535:
                raise ValueError(f"Port {port} out of valid range 1-65535.")
            ports.add(port)
    return sorted(ports)


def resolve_target(target: str) -> Tuple[bool, str, str]:
    """
    Resolve a target to its canonical IP address.

    Returns (is_valid, resolved_ip, error_message).
    """
    target = target.strip()
    if validate_ip(target):
        return True, target, ""
    try:
        resolved = socket.gethostbyname(target)
        return True, resolved, ""
    except socket.gaierror as exc:
        return False, "", f"DNS resolution failed: {exc}"


def parse_targets(target_input: str) -> Tuple[List[str], str]:
    """
    Parse target input into a flat list of IP addresses.

    Accepts: single IP, CIDR range, hostname, IP range (192.168.1.1-254).
    Returns (list_of_ips, error_message).
    """
    target = target_input.strip()
    if not target:
        return [], "Target cannot be empty."

    # CIDR notation
    if "/" in target and validate_cidr(target):
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 4096:
            return [], (
                f"Network too large: {network.num_addresses} addresses. Maximum 4096."
            )
        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]
        return [str(ip) for ip in hosts], ""

    # IP range like 192.168.1.1-254
    range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if range_match:
        prefix, start_str, end_str = range_match.groups()
        start, end = int(start_str), int(end_str)
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            return [], "Invalid IP range. Ensure start <= end and octets are 0-255."
        return [f"{prefix}{i}" for i in range(start, end + 1)], ""

    # Single IP
    if validate_ip(target):
        return [target], ""

    # Hostname
    valid, resolved, error = resolve_target(target)
    if valid:
        return [resolved], ""
    return [], error
