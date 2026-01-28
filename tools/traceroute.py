import os
import socket
import time
from typing import List, Tuple


def _resolve_target(target: str) -> Tuple[str, int]:
    info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not info:
        raise ValueError("Unable to resolve target.")
    return info[0][4][0], info[0][0]


def _format_hop(ttl: int, addr: str, rtts: List[float]) -> str:
    if not addr:
        return f"{ttl:2d}  " + "  ".join("*" for _ in rtts)
    parts = []
    for rtt in rtts:
        if rtt < 0:
            parts.append("*")
        else:
            parts.append(f"{rtt:.1f} ms")
    rtt_str = "  ".join(parts)
    return f"{ttl:2d}  {addr}  {rtt_str}".rstrip()


def run_traceroute(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    probes: int = 3,
    base_port: int = 33434,
) -> Tuple[List[str], str]:
    if os.name == "nt":
        return [], "Built-in traceroute requires Linux/macOS raw sockets. Use Linux or install traceroute."
    try:
        dest_ip, family = _resolve_target(target)
    except Exception as exc:
        return [], str(exc)

    if family not in (socket.AF_INET, socket.AF_INET6):
        return [], "Unsupported address family."

    lines: List[str] = []

    for ttl in range(1, max_hops + 1):
        hop_addr = ""
        rtts: List[float] = []
        reached = False

        for probe in range(probes):
            recv_socket = None
            send_socket = None
            try:
                if family == socket.AF_INET:
                    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    dest = (dest_ip, base_port + probe)
                else:
                    recv_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
                    send_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
                    dest = (dest_ip, base_port + probe, 0, 0)

                recv_socket.settimeout(timeout)
                send_socket.settimeout(timeout)

                start = time.time()
                send_socket.sendto(b"", dest)

                try:
                    _, addr = recv_socket.recvfrom(512)
                    elapsed = (time.time() - start) * 1000.0
                    hop_addr = addr[0]
                    rtts.append(elapsed)
                    if hop_addr == dest_ip:
                        reached = True
                except socket.timeout:
                    rtts.append(-1.0)
            except PermissionError:
                return [], "Permission denied. Traceroute requires raw socket access (root or CAP_NET_RAW)."
            except OSError as exc:
                return [], str(exc)
            finally:
                if send_socket:
                    send_socket.close()
                if recv_socket:
                    recv_socket.close()

        lines.append(_format_hop(ttl, hop_addr, rtts))
        if reached:
            break

    return lines, ""
