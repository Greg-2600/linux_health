from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List

COMMON_PORTS = [
    22,
    80,
    443,
    8080,
    8443,
    3306,
    5432,
    6379,
    3389,
    25,
    110,
    143,
    993,
    995,
    53,
    111,
    139,
    445,
    2049,
    21,
    23,
    5900,
    9200,
    27017,
]


@dataclass
class PortStatus:
    port: int
    open: bool
    reason: str | None = None


def _scan_single(host: str, port: int, timeout: float) -> PortStatus:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return PortStatus(port=port, open=True, reason="Connected")
        except socket.timeout:
            return PortStatus(port=port, open=False, reason="timeout")
        except OSError as exc:
            return PortStatus(port=port, open=False, reason=str(exc))


def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.7, max_workers: int = 50) -> List[PortStatus]:
    unique_ports = sorted({int(p) for p in ports if int(p) > 0})
    results: list[PortStatus] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(_scan_single, host, port, timeout): port for port in unique_ports}
        for future in as_completed(future_to_port):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)
