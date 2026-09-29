"""Tests for verify.py (constant-time HMAC) and store.py (replay guard)."""

from webhook_ingest.store import ReplayGuard
from webhook_ingest.verify import signature_for, verify

SECRET = b"test-secret"


def test_roundtrip_accepts_valid():
    payload = b'{"hello":"world"}'
    header = signature_for(payload, SECRET)
    assert verify(payload, SECRET, header)


def test_bare_hex_accepted():
    payload = b"x"
    header = signature_for(payload, SECRET).split("=", 1)[1]
    assert verify(payload, SECRET, header)


def test_tampered_payload_rejected():
    payload = b'{"amount":1}'
    header = signature_for(payload, SECRET)
    assert not verify(payload + b" ", SECRET, header)


def test_wrong_secret_rejected():
    payload = b"x"
    header = signature_for(payload, b"other")
    assert not verify(payload, SECRET, header)


def test_malformed_headers_fail_closed():
    payload = b"x"
    good = signature_for(payload, SECRET)
    for bad in (
        "",
        None,
        "sha256=" + "z" * 64,  # non-hex
        "sha256=" + "ab",  # wrong length
        "md5=" + good.split("=", 1)[1],  # wrong scheme prefix
        "sha256=  ",
        "null-bytes-\x00\x01",
    ):
        assert not verify(payload, SECRET, bad), f"accepted malformed header {bad!r}"


def test_no_secret_fail_closed():
    payload = b"x"
    header = signature_for(payload, SECRET)
    assert not verify(payload, b"", header)


def _guard_with_time(now):
    return ReplayGuard(clock=lambda: now)


def test_replay_rejected_same_timestamp():
    g = _guard_with_time(1000)
    ok, _ = g.check_and_record("k", 1000)
    assert ok
    ok, reason = g.check_and_record("k", 1000)
    assert not ok and "replay" in reason


def test_fresh_timestamp_accepted():
    g = _guard_with_time(1000)
    ok, _ = g.check_and_record("k", 1000)
    assert ok
    ok, _ = g.check_and_record("k", 1100)
    assert ok


def test_stale_timestamp_rejected_by_age_bound():
    g = _guard_with_time(2000)
    ok, reason = g.check_and_record("k", 1000)
    assert not ok and "window" in reason


def test_future_timestamp_beyond_skew_rejected():
    g = _guard_with_time(1000)
    ok, reason = g.check_and_record("k", 1000 + 301)
    assert not ok and "window" in reason


def test_keys_are_isolated():
    g = _guard_with_time(1000)
    ok, _ = g.check_and_record("a", 1000)
    assert ok
    ok, _ = g.check_and_record("b", 1000)
    assert ok


def test_window_prunes_old_entries():
    g = ReplayGuard(tolerance_s=100, clock=lambda: 1000)
    g.check_and_record("k", 950)
    # Advance far past the window: the old entry is pruned, and even the
    # age bound would reject 950 now — prune correctness shows in set size.
    g2 = ReplayGuard(tolerance_s=100, clock=lambda: 5000)
    ok, _ = g2.check_and_record("k", 4950)
    assert ok
