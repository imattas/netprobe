import socket
import concurrent.futures
from typing import Iterable, List, Optional, Tuple


def get_service_info(ip: str, port: int, timeout: float = 0.5) -> Optional[Tuple[int, str]]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))

        if result == 0:
            banner = ""
            try:
                # Try to receive a banner/initial response
                data = s.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
                else:
                    # Some services might not send a banner immediately,
                    # try sending a simple HTTP HEAD request
                    request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode()
                    s.sendall(request)
                    data = s.recv(1024)
                    if data:
                        banner = data.decode(errors="ignore").strip()
            except socket.error:
                banner = ""
            finally:
                s.close()

            if banner:
                return port, f"Port {port} is OPEN | Service Info: {banner[:100]} ..."
            return port, f"Port {port} is OPEN"

        # Port closed or filtered
        s.close()
        return None

    except socket.error:
        # Any socket error -> treat as no info
        return None


def scan_port_list(
    target_ip: str,
    ports: Iterable[int],
    max_workers: int = 100,
    timeout: float = 0.5,
) -> List[str]:

    open_ports_info: List[Tuple[int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_service_info, target_ip, port, timeout): port
            for port in sorted(set(ports))
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports_info.append(result)

    open_ports_info.sort(key=lambda item: item[0])
    return [info for _, info in open_ports_info]
