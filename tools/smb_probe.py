import os
import socket
import struct
from typing import Dict, Optional

from tools.target_parse import parse_host_port


_DIALECTS = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]


def _netbios_wrap(payload: bytes) -> bytes:
    length = len(payload)
    return b"\x00" + struct.pack(">I", length)[1:]


def _build_negotiate_request() -> bytes:
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", 0)
        + (b"\x00" * 16)
    )

    dialects = b"".join(struct.pack("<H", d) for d in _DIALECTS)
    client_guid = os.urandom(16)

    negotiate = (
        struct.pack("<H", 36)
        + struct.pack("<H", len(_DIALECTS))
        + struct.pack("<H", 1)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + client_guid
        + struct.pack("<I", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + dialects
    )

    packet = header + negotiate
    return _netbios_wrap(packet) + packet


def _recv_full(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _parse_smb2_response(payload: bytes) -> Dict[str, Optional[str]]:
    if len(payload) < 70:
        return {"smb2": "yes", "dialect": "unknown", "signing_required": "unknown"}

    offset = 64
    security_mode = struct.unpack("<H", payload[offset + 2 : offset + 4])[0]
    dialect = struct.unpack("<H", payload[offset + 4 : offset + 6])[0]

    return {
        "smb2": "yes",
        "dialect": f"0x{dialect:04x}",
        "signing_required": "yes" if (security_mode & 0x02) else "no",
    }


def probe_smb(target: str, timeout: float = 2.0) -> Dict[str, str]:
    host, port = parse_host_port(target, 445)
    request = _build_negotiate_request()

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)

        header = _recv_full(sock, 4)
        if len(header) < 4:
            return {"host": host, "port": str(port), "error": "No response."}

        length = struct.unpack(">I", b"\x00" + header[1:])[0]
        payload = _recv_full(sock, length)
        if len(payload) < 4:
            return {"host": host, "port": str(port), "error": "Short response."}

        if payload.startswith(b"\xfeSMB"):
            info = _parse_smb2_response(payload)
            info["host"] = host
            info["port"] = str(port)
            return info

        if payload.startswith(b"\xffSMB"):
            return {"host": host, "port": str(port), "smb1": "yes"}

        return {"host": host, "port": str(port), "error": "Unknown response."}
