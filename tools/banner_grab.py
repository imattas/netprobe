import concurrent.futures
import socket
import ssl
from typing import Iterable, List, Optional, Tuple


_HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 5000}
_HTTPS_PORTS = {443, 8443}
_SMTP_PORTS = {25, 465, 587}
_FTP_PORTS = {21}
_POP3_PORTS = {110, 995}
_IMAP_PORTS = {143, 993}
_REDIS_PORTS = {6379}


def _resolve_target(target: str, port: int) -> Tuple[str, int, int]:
    infos = socket.getaddrinfo(target, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise ValueError("Unable to resolve target.")
    family, _, _, _, sockaddr = infos[0]
    if family == socket.AF_INET6:
        ip, port, _, scopeid = sockaddr
        return ip, port, scopeid
    ip, port = sockaddr
    return ip, port, 0


def _read_data(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(1024)
    except socket.timeout:
        return b""


def _send_and_read(sock: socket.socket, payload: bytes, timeout: float) -> bytes:
    try:
        sock.sendall(payload)
        return _read_data(sock, timeout)
    except OSError:
        return b""


def grab_banner(target: str, port: int, timeout: float = 1.0) -> Optional[str]:
    ip, port, scopeid = _resolve_target(target, port)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if family == socket.AF_INET6:
            sock.connect((ip, port, 0, scopeid))
        else:
            sock.connect((ip, port))

        data = _read_data(sock, timeout)
        if not data:
            data = _probe_service(sock, target, port, timeout)

        if not data:
            return None

        text = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
        return text[:200]
    except OSError:
        return None
    finally:
        sock.close()


def _probe_service(sock: socket.socket, host: str, port: int, timeout: float) -> bytes:
    if port in _HTTP_PORTS:
        payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netprobe\r\n\r\n".encode()
        return _send_and_read(sock, payload, timeout)

    if port in _SMTP_PORTS:
        return _send_and_read(sock, b"EHLO netprobe\r\n", timeout)

    if port in _FTP_PORTS:
        return _send_and_read(sock, b"NOOP\r\n", timeout)

    if port in _POP3_PORTS:
        return _send_and_read(sock, b"NOOP\r\n", timeout)

    if port in _IMAP_PORTS:
        return _send_and_read(sock, b"A1 CAPABILITY\r\n", timeout)

    if port in _REDIS_PORTS:
        return _send_and_read(sock, b"*1\r\n$4\r\nPING\r\n", timeout)

    if port in _HTTPS_PORTS:
        return _probe_https(sock, host, port, timeout)

    return b""


def _probe_https(sock: socket.socket, host: str, port: int, timeout: float) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netprobe\r\n\r\n".encode()
            return _send_and_read(tls_sock, payload, timeout)
    except OSError:
        return b""


def scan_banners(
    target: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = 100,
) -> List[str]:
    results: List[Tuple[int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(grab_banner, target, port, timeout): port
            for port in sorted(set(ports))
        }

        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            banner = future.result()
            if banner:
                results.append((port, f"Port {port} | {banner}"))

    results.sort(key=lambda item: item[0])
    return [info for _, info in results]
