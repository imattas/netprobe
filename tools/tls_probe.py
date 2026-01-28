import ipaddress
import socket
import ssl
from typing import Dict, List

from tools.target_parse import parse_host_port


_TLS13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

_TLS12_CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _try_handshake(host: str, port: int, timeout: float, context: ssl.SSLContext, sni: str | None):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            return ssock.cipher(), ssock.version()


def probe_tls_ciphers(target: str, timeout: float = 3.0) -> Dict[str, List[dict]]:
    host, port = parse_host_port(target, 443)
    sni = None if _is_ip(host) else host

    supported: List[dict] = []
    errors: List[str] = []

    for cipher in _TLS12_CIPHERS:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers(cipher)
            selected, version = _try_handshake(host, port, timeout, context, sni)
            supported.append({"cipher": selected[0], "version": version})
        except ssl.SSLError:
            continue
        except OSError as exc:
            errors.append(str(exc))
            break

    tls13_supported = False
    if hasattr(ssl.SSLContext, "set_ciphersuites"):
        for cipher in _TLS13_CIPHERS:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.set_ciphersuites(cipher)
                selected, version = _try_handshake(host, port, timeout, context, sni)
                supported.append({"cipher": selected[0], "version": version})
                tls13_supported = True
            except ssl.SSLError:
                continue
            except OSError as exc:
                errors.append(str(exc))
                break
    else:
        errors.append("TLS 1.3 ciphersuite probing not supported by this Python/OpenSSL build.")

    return {
        "host": host,
        "port": str(port),
        "supported": supported,
        "errors": errors,
    }
