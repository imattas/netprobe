def parse_host_port(target: str, default_port: int) -> tuple[str, int]:
    target = target.strip()
    if not target:
        raise ValueError("Empty target.")

    if target.startswith("["):
        end = target.find("]")
        if end == -1:
            raise ValueError("Invalid IPv6 bracket notation.")
        host = target[1:end].strip()
        if not host:
            raise ValueError("Invalid host.")
        rest = target[end + 1 :].strip()
        port = default_port
        if rest:
            if not rest.startswith(":"):
                raise ValueError("Invalid target format.")
            port_str = rest[1:]
            if not port_str.isdigit():
                raise ValueError("Invalid port.")
            port = int(port_str)
        _validate_port(port)
        return host, port

    if target.count(":") == 1:
        host, port_str = target.rsplit(":", 1)
        if port_str.isdigit():
            port = int(port_str)
            _validate_port(port)
            return host, port

    _validate_port(default_port)
    return target, default_port


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError("Port out of range.")
