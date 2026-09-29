"""Replay protection: per-key sliding window of seen signature timestamps.

A valid HMAC proves authenticity; it does NOT prove freshness. Any capture-
and-replay of a legitimate signed payload would pass verification forever
unless the receiver bounds message age. This module keeps, per signing key,
the timestamps of accepted messages within the tolerance window and rejects
a message whose (key, timestamp) pair was already accepted — so an attacker
replaying a captured request inside the window hits the dedupe, and outside
the window hits the age bound.

Deliberately in-process (a set per key): honest about scope. Multi-worker
deployments need a shared store (Redis SETNX or similar) — the module doc
says so rather than pretending a dict is distributed.
"""

from __future__ import annotations

import time
from threading import Lock

DEFAULT_TOLERANCE_S = 300  # five minutes: generous clock skew, tight replay


class ReplayGuard:
    def __init__(self, tolerance_s: int = DEFAULT_TOLERANCE_S, clock=None):
        self._tolerance = tolerance_s
        self._clock = clock or time.time
        self._seen: dict[str, set[int]] = {}
        self._lock = Lock()

    def check_and_record(self, key_id: str, timestamp: int) -> tuple[bool, str]:
        """Return (accepted, reason). Accepted messages are recorded.

        Order matters: age bound FIRST (cheap, stateless), then dedupe.
        """
        now = int(self._clock())
        if abs(now - timestamp) > self._tolerance:
            return False, f"timestamp outside +/-{self._tolerance}s window"
        ts_ms = timestamp
        with self._lock:
            seen = self._seen.setdefault(key_id, set())
            if ts_ms in seen:
                return False, "replay: this key+timestamp was already accepted"
            seen.add(ts_ms)
            self._prune(seen, now)
        return True, "ok"

    def _prune(self, seen: set[int], now: int) -> None:
        """Drop entries older than the window so the set cannot grow unbounded."""
        horizon = now - self._tolerance
        seen.difference_update(ts for ts in seen if ts < horizon)
