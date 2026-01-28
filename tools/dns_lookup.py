import ipaddress
import socket
from typing import Dict, List


def _unique_sorted(values: List[str]) -> List[str]:
    return sorted(set(values))


def lookup(target: str) -> Dict[str, List[str]]:
    result = {"target": target, "addresses": [], "names": []}

    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        try:
            host, aliases, addrs = socket.gethostbyaddr(target)
        except (socket.herror, socket.gaierror) as exc:
            raise ValueError(str(exc)) from exc

        result["names"] = _unique_sorted([host] + aliases)
        result["addresses"] = _unique_sorted(addrs)
        return result

    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(str(exc)) from exc

    addresses = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addresses.append(sockaddr[0])

    if not addresses:
        raise ValueError("No addresses found.")

    result["addresses"] = _unique_sorted(addresses)
    return result
