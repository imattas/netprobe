import concurrent.futures
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
from typing import Iterable, List, Sequence, Tuple


def _is_ipv6(target: str) -> bool:
    return ":" in target


def _ping_available() -> bool:
    return shutil.which("ping") is not None


def _build_ping_command(target: str, timeout: float) -> List[str]:
    timeout_s = max(1, int(timeout))
    timeout_ms = max(1, int(timeout * 1000))

    if not _ping_available():
        return []

    if sys.platform.startswith("linux"):
        cmd = ["ping", "-c", "1", "-W", str(timeout_s)]
        if _is_ipv6(target):
            cmd.insert(1, "-6")
        cmd.append(target)
        return cmd

    if sys.platform.startswith("darwin"):
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms)]
        if _is_ipv6(target):
            cmd.insert(1, "-6")
        cmd.append(target)
        return cmd

    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
        return cmd

    return ["ping", "-c", "1", target]


def ping_host(target: str, timeout: float = 1.0) -> bool:
    cmd = _build_ping_command(target, timeout)
    if not cmd:
        return False

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False

    return result.returncode == 0


def tcp_ping(
    target: str,
    ports: Sequence[int],
    timeout: float = 0.5,
) -> bool:
    family = socket.AF_INET6 if _is_ipv6(target) else socket.AF_INET
    for port in ports:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((target, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def _expand_targets(target: str) -> List[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        ip = ipaddress.ip_address(target)
        network = ipaddress.ip_network(f"{ip}/32", strict=False)

    return [str(ip) for ip in network.hosts()]


def discover_hosts(
    target: str,
    timeout: float = 1.0,
    max_workers: int = 100,
    tcp_fallback_ports: Sequence[int] = (80, 443, 22),
) -> Tuple[List[str], str]:
    targets = _expand_targets(target)
    if not targets:
        return [], "none"

    ping_available = _ping_available()
    used_tcp_fallback = False
    live_hosts: List[str] = []

    def check_host(ip: str) -> Tuple[str, bool, bool]:
        alive = False
        used_tcp = False
        if ping_available:
            alive = ping_host(ip, timeout=timeout)
        if not alive and tcp_fallback_ports:
            if tcp_ping(ip, tcp_fallback_ports, timeout=min(timeout, 1.0)):
                alive = True
                used_tcp = True
        return ip, alive, used_tcp

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_host, ip) for ip in targets]
        for future in concurrent.futures.as_completed(futures):
            ip, alive, used_tcp = future.result()
            if alive:
                live_hosts.append(ip)
            if used_tcp:
                used_tcp_fallback = True

    live_hosts.sort(key=lambda ip: ipaddress.ip_address(ip))

    if not ping_available and tcp_fallback_ports:
        method = "tcp"
    elif ping_available and used_tcp_fallback:
        method = "icmp+tcp"
    elif ping_available:
        method = "icmp"
    else:
        method = "none"

    return live_hosts, method
