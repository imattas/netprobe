import socket
from typing import Dict

from tools.target_parse import parse_host_port


def get_ssh_banner(target: str, timeout: float = 2.0) -> Dict[str, str]:
    host, port = parse_host_port(target, 22)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = sock.recv(255)
        banner = data.decode(errors="ignore").strip()
        if not banner.startswith("SSH-"):
            # Some servers wait for a client hello; send a minimal one.
            try:
                sock.sendall(b"SSH-2.0-netprobe\r\n")
                data = sock.recv(255)
                banner = data.decode(errors="ignore").strip()
            except OSError:
                pass

    return {"host": host, "port": str(port), "banner": banner or "n/a"}
