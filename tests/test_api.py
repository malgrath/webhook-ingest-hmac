"""API contract tests: signed end-to-end flows through the ASGI app.

No network: httpx's ASGITransport drives the app in-process. The signing
helper mirrors what a real sender does (construct the exact body bytes,
sign them, ship the header) — the property that matters here is that the
receiver verifies the SAME raw bytes the sender signed.
"""

import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

import webhook_ingest.app as app_module
from webhook_ingest.app import app

SECRET = b"ci-secret"


def _sign(payload: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


def _client(secret: bytes = SECRET) -> TestClient:
    app_module.SECRET = secret
    app_module._guard = app_module.ReplayGuard(clock=time.time)
    return TestClient(app)


def _body(**over) -> bytes:
    data = {"key_id": "k1", "timestamp": int(time.time()), **over}
    return json.dumps(data).encode()


def test_health():
    with _client() as c:
        assert c.get("/health").status_code == 200


def test_signed_payload_accepted():
    with _client() as c:
        raw = _body()
        r = c.post("/ingest", content=raw, headers={"X-Signature-256": _sign(raw)})
        assert r.status_code == 200
        assert r.json()["accepted"] is True


def test_unsigned_rejected():
    with _client() as c:
        r = c.post("/ingest", content=_body())
        assert r.status_code == 401


def test_wrong_signature_rejected():
    with _client() as c:
        raw = _body()
        r = c.post(
            "/ingest",
            content=raw,
            headers={"X-Signature-256": _sign(b"different bytes")},
        )
        assert r.status_code == 401


def test_replay_of_identical_signed_request_rejected():
    with _client() as c:
        raw = _body()
        headers = {"X-Signature-256": _sign(raw)}
        assert c.post("/ingest", content=raw, headers=headers).status_code == 200
        r = c.post("/ingest", content=raw, headers=headers)
        assert r.status_code == 409
        assert "replay" in r.json()["detail"]


def test_stale_timestamp_rejected_even_when_signed():
    with _client() as c:
        raw = _body(timestamp=int(time.time()) - 4000)
        r = c.post("/ingest", content=raw, headers={"X-Signature-256": _sign(raw)})
        assert r.status_code == 409
        assert "window" in r.json()["detail"]


def test_payload_without_timestamp_rejected():
    with _client() as c:
        raw = json.dumps({"key_id": "k1"}).encode()
        r = c.post("/ingest", content=raw, headers={"X-Signature-256": _sign(raw)})
        assert r.status_code == 400


def test_unconfigured_service_fails_closed():
    with _client(secret=b"") as c:
        raw = _body()
        r = c.post("/ingest", content=raw, headers={"X-Signature-256": _sign(raw)})
        assert r.status_code == 503


def test_signing_oracle_disabled_when_secret_configured():
    with _client() as c:
        r = c.get("/signature-for", params={"payload": "x"})
        assert r.status_code == 403


def test_signing_oracle_available_in_demo_mode():
    with _client(secret=b"") as c:
        r = c.get("/signature-for", params={"payload": "x"})
        assert r.status_code == 200
        assert r.json()["header"].startswith("sha256=")
