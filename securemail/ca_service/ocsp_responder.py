"""OCSP-lite: trả về 'good' / 'revoked' / 'unknown' cho 1 serial."""
from . import ca_core


def check(serial_hex: str) -> str:
    return ca_core.check_status(serial_hex)
