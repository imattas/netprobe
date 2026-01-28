import concurrent.futures
from typing import Iterable, List, Tuple

from tools import host_discovery, port_scan


def scan_live_hosts(
    target: str,
    ports: Iterable[int],
    ping_timeout: float = 1.0,
    scan_timeout: float = 0.5,
    max_host_workers: int = 10,
    per_host_workers: int = 50,
) -> Tuple[List[Tuple[str, List[str]]], str]:
    live_hosts, method = host_discovery.discover_hosts(target, timeout=ping_timeout)
    if not live_hosts:
        return [], method

    results: List[Tuple[str, List[str]]] = []

    def scan_host(host: str) -> Tuple[str, List[str]]:
        open_ports = port_scan.scan_port_list(
            host,
            ports,
            max_workers=per_host_workers,
            timeout=scan_timeout,
        )
        return host, open_ports

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_host_workers) as executor:
        futures = [executor.submit(scan_host, host) for host in live_hosts]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: item[0])
    return results, method
