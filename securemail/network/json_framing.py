"""Length-prefix JSON framing over TCP socket.

Frame = 4-byte big-endian length || UTF-8 JSON bytes.
Hỗ trợ base64 encode cho binary field tự động qua key helper.
"""
import base64
import json
import socket
import struct


MAX_FRAME = 16 * 1024 * 1024  # 16 MB


def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("frame too large")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def recv_json(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length > MAX_FRAME:
        raise ValueError(f"frame too large: {length}")
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def request(host: str, port: int, obj: dict, timeout: float = 10.0) -> dict:
    """One-shot request/response."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        send_json(s, obj)
        return recv_json(s)
