"""MIME-lite: build / parse text email với header dict.

Format đơn giản:
  Key: value\r\n
  ...
  \r\n
  body...
"""


def build(headers: dict, body: bytes) -> bytes:
    lines = []
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    header_block = "\r\n".join(lines).encode("utf-8")
    return header_block + b"\r\n\r\n" + body


def parse(raw: bytes) -> tuple[dict, bytes]:
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        idx2 = raw.find(b"\n\n")
        if idx2 < 0:
            raise ValueError("no header/body separator")
        header_raw = raw[:idx2]
        body = raw[idx2 + 2:]
    else:
        header_raw = raw[:idx]
        body = raw[idx + 4:]

    headers = {}
    for line in header_raw.decode("utf-8", errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, body


def canonicalize_relaxed(headers: dict, header_names: list[str], body: bytes) -> bytes:
    """DKIM relaxed/relaxed canonicalization (simplified).

    Header: lowercase name, collapse WS in value, one line per header.
    Body: strip trailing blank lines, ignore whitespace at line end.
    """
    h_lines = []
    for name in header_names:
        for k, v in headers.items():
            if k.lower() == name.lower():
                cv = " ".join(v.split())
                h_lines.append(f"{k.lower()}:{cv}")
                break
    h_block = "\r\n".join(h_lines).encode("utf-8")

    b_lines = body.splitlines()
    while b_lines and b_lines[-1].strip() == b"":
        b_lines.pop()
    b_clean = b"\r\n".join(b" ".join(l.split()) for l in b_lines)
    if b_clean:
        b_clean += b"\r\n"
    return h_block + b"\r\n" + b_clean
