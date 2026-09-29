"""Signature verification primitives (pure functions, no I/O).

The security story of this service lives here:

- **Constant-time compare** via ``hmac.compare_digest`` — never ``==`` on
  secrets (string equality short-circuits and leaks timing).
- **Length tolerance without panic**: GitHub signs with ``sha256=...`` and
  some senders with the bare hex; both parse, garbage does not.
- **Fail-closed**: any malformed input returns False, never raises past the
  boundary.
- **Replay guard** lives in ``store.py``; this module stays pure so it is
  trivially testable.
"""

from __future__ import annotations

import hashlib
import hmac

SCHEME = "sha256"
_HEX_DIGITS = set("0123456789abcdef")


def signature_for(payload: bytes, secret: bytes) -> str:
    """The exact header value a sender should ship: ``sha256=<hex>``."""
    digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"{SCHEME}={digest}"


def _parse_header(value: str) -> bytes | None:
    """Extract the raw digest bytes from a signature header value.

    Accepts ``sha256=<hex>`` and bare ``<hex>``; rejects anything else
    (wrong length, non-hex characters, empty) by returning None.
    """
    if not value:
        return None
    v = value.strip()
    if v.lower().startswith(SCHEME + "="):
        v = v[len(SCHEME) + 1 :]
    v = v.strip().lower()
    if len(v) != hashlib.sha256().digest_size * 2:
        return None
    if not set(v) <= _HEX_DIGITS:
        return None
    return bytes.fromhex(v)


def verify(payload: bytes, secret: bytes, header_value: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification. Fail-closed on any malformed input."""
    if not header_value or not secret:
        return False
    provided = _parse_header(header_value)
    if provided is None:
        return False
    expected = hmac.new(secret, payload, hashlib.sha256).digest()
    return hmac.compare_digest(provided, expected)
