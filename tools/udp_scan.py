import concurrent.futures
import socket
from typing import Iterable, List, Optional, Sequence, Tuple


def _resolve_target(target: str) -> Tuple[str, int, int]:
    infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not infos:
        raise ValueError("Unable to resolve target.")
    family, _, _, _, sockaddr = infos[0]
    if family == socket.AF_INET6:
        ip, _, flowinfo, scopeid = sockaddr
        return ip, family, scopeid
    ip, _ = sockaddr
    return ip, family, 0


def _scan_udp_port(
    target_ip: str,
    family: int,
    scopeid: int,
    port: int,
    timeout: float,
    payload: bytes,
) -> Tuple[int, str]:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        if family == socket.AF_INET6:
            sock.connect((target_ip, port, 0, scopeid))
        else:
            sock.connect((target_ip, port))

        sock.send(payload)
        try:
            data = sock.recv(1024)
            if data:
                return port, f"Port {port} is OPEN (response)"
            return port, f"Port {port} is OPEN (no data)"
        except socket.timeout:
            return port, f"Port {port} is OPEN|FILTERED"
        except ConnectionRefusedError:
            return port, f"Port {port} is CLOSED"
    finally:
        sock.close()


def scan_udp_ports(
    target: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = 100,
    payload: Optional[bytes] = None,
) -> List[str]:
    target_ip, family, scopeid = _resolve_target(target)
    payload = payload if payload is not None else b"\x00"

    results: List[Tuple[int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _scan_udp_port,
                target_ip,
                family,
                scopeid,
                port,
                timeout,
                payload,
            ): port
            for port in sorted(set(ports))
        }

        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except OSError:
                results.append((port, f"Port {port} scan failed"))

    results.sort(key=lambda item: item[0])
    return [info for _, info in results]
