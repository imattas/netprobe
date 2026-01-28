import http.client
import ssl
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


def _flatten_name(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_target(target: str) -> Tuple[str, str, int, str]:
    if "://" not in target:
        target = f"http://{target}"

    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError("Invalid URL or host.")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme}")

    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return scheme, host, port, path


def probe_http(target: str, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    scheme, host, port, path = _parse_target(target)

    if scheme == "https":
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    start = time.time()
    conn.request("HEAD", path, headers={"User-Agent": "netprobe"})
    response = conn.getresponse()
    elapsed = time.time() - start

    headers = dict(response.getheaders())
    server = headers.get("Server", "")
    content_length = headers.get("Content-Length", "")

    tls_info = None
    if scheme == "https":
        try:
            cert = conn.sock.getpeercert()
            tls_info = {
                "subject": _flatten_name(cert.get("subject")),
                "issuer": _flatten_name(cert.get("issuer")),
                "not_after": cert.get("notAfter"),
            }
        except Exception:
            tls_info = None

    conn.close()

    return {
        "scheme": scheme,
        "host": host,
        "port": str(port),
        "path": path,
        "status": str(response.status),
        "reason": response.reason,
        "server": server,
        "content_length": content_length,
        "elapsed_ms": f"{elapsed * 1000:.2f}",
        "tls_subject": tls_info["subject"] if tls_info else "",
        "tls_issuer": tls_info["issuer"] if tls_info else "",
        "tls_not_after": tls_info["not_after"] if tls_info else "",
    }
