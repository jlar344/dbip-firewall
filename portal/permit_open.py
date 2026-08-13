"""Parse and validate DBIP_PERMIT_OPEN destinations.

Accepted form (comma-separated):
    127.0.0.1:6432
    127.0.0.1:3306,127.0.0.1:6432
    [::1]:5432

Rejected: SSH options, quotes, wildcards, commands, non-numeric ports.
"""
from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable

PERMIT_OPEN_ENV = "DBIP_PERMIT_OPEN"
CONFIG_FILES = (
    os.environ.get("DBIP_PERMIT_OPEN_FILE", "/etc/db-ip-portal/permit-open.conf"),
    os.environ.get("DBIP_ENV_FILE", "/etc/db-ip-portal/db-ip-portal.env"),
)

# host:port  OR  [ipv6]:port — no spaces, quotes, or SSH tokens
_V4_OR_NAME = re.compile(
    r"^(?P<host>localhost|127\.0\.0\.1|(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})$"
)
_V6 = re.compile(r"^\[(?P<host>[0-9a-fA-F:]+)\]:(?P<port>\d{1,5})$")


class PermitOpenError(ValueError):
    pass


def _validate_host_port(host: str, port_s: str) -> tuple[str, int]:
    try:
        port = int(port_s, 10)
    except ValueError as exc:
        raise PermitOpenError(f"invalid port: {port_s}") from exc
    if port < 1 or port > 65535:
        raise PermitOpenError(f"port out of range: {port}")
    if host.lower() == "localhost":
        return "127.0.0.1", port
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise PermitOpenError(f"invalid host: {host}") from exc
    if isinstance(ip, ipaddress.IPv6Address):
        return f"[{ip.compressed}]", port
    return str(ip), port


def parse_permit_open(raw: str) -> list[tuple[str, int]]:
    if raw is None:
        raise PermitOpenError("empty permit-open list")
    text = raw.strip()
    if not text:
        raise PermitOpenError("empty permit-open list")
    forbidden = set(" \t\r\n\"'=*;")
    if any(c in text for c in forbidden):
        raise PermitOpenError("permit-open contains forbidden characters")
    seen: list[tuple[str, int]] = []
    for item in text.split(","):
        if not item:
            raise PermitOpenError("empty destination")
        match = _V6.fullmatch(item) or _V4_OR_NAME.fullmatch(item)
        if not match:
            raise PermitOpenError(f"invalid destination: {item}")
        dest = _validate_host_port(match.group("host"), match.group("port"))
        if dest not in seen:
            seen.append(dest)
    if not seen:
        raise PermitOpenError("empty permit-open list")
    return seen


def format_csv(destinations: Iterable[tuple[str, int]]) -> str:
    return ",".join(f"{host}:{port}" for host, port in destinations)


def format_sshd_permitopen(destinations: Iterable[tuple[str, int]]) -> str:
    return " ".join(f"{host}:{port}" for host, port in destinations)


def key_options_prefix(destinations: Iterable[tuple[str, int]] | None = None) -> str:
    dests = list(destinations) if destinations is not None else load_permit_open()
    parts = ["restrict", "port-forwarding"]
    parts.extend(f'permitopen="{host}:{port}"' for host, port in dests)
    return ",".join(parts) + " "


def local_listen_port(dest_port: int) -> int:
    """Client-side -L port: dest+10000 when it fits, else dest_port."""
    candidate = dest_port + 10000
    if 1 <= candidate <= 65535:
        return candidate
    return dest_port


def _read_assignment(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(PERMIT_OPEN_ENV + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def load_permit_open() -> list[tuple[str, int]]:
    raw = os.environ.get(PERMIT_OPEN_ENV)
    if raw:
        return parse_permit_open(raw)
    for path in CONFIG_FILES:
        raw = _read_assignment(path)
        if raw:
            return parse_permit_open(raw)
    raise PermitOpenError(
        f"{PERMIT_OPEN_ENV} is not set and no config file provided a value"
    )
