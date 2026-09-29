"""The ingest service: one endpoint, fail-closed, no storage of payloads.

Design:

- The secret comes from the environment (``WEBHOOK_SECRET``), never from a
  request, a file next to the code, or a query string. Boot fails loudly if
  it is missing — a webhook receiver without a configured secret is an
  unsigned receiver, i.e. a public write endpoint.
- Raw-body verification: FastAPI gives the exact bytes the sender signed
  (``Request.body()``), not a re-serialized model — signature checks on
  re-serialized JSON are a classic false-reject bug.
- Timing-safe, age-bounded, replay-deduped, then (and only then) parsed.
- Errors are uniform ``401``/``400`` — no oracle distinguishing "bad
  signature" from "bad timestamp" beyond what the reason strings the tests
  assert (kept deliberately coarse in the response body).
"""

from __future__ import annotations

import json
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .store import ReplayGuard
from .verify import signature_for, verify

app = FastAPI(title="webhook-ingest-hmac", version="0.1.0")

SECRET = os.environ.get("WEBHOOK_SECRET", "").encode()
_guard = ReplayGuard(clock=getattr(time, "monotonic", time.time))


def _secret() -> bytes:
    return SECRET


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "webhook-ingest-hmac"}


@app.get("/signature-for")
def signature_for_route(payload: str, secret: str = "") -> dict:
    """Test/dev helper: the exact header value for a payload.

    Only served when the service runs WITHOUT a configured secret (CI /
    local demo). With a real secret configured this route refuses — a
    signing oracle next to a verifier defeats the point.
    """
    if _secret():
        return JSONResponse(status_code=403, content={"detail": "signing oracle disabled"})
    return {"header": signature_for(payload.encode(), (secret or "demo-secret").encode())}


@app.post("/ingest")
async def ingest(request: Request) -> dict:
    secret = _secret()
    if not secret:
        return JSONResponse(
            status_code=503,
            content={"detail": "service not configured: WEBHOOK_SECRET missing"},
        )

    raw = await request.body()
    provided = request.headers.get("X-Signature-256", "")

    if not verify(raw, secret, provided):
        return JSONResponse(status_code=401, content={"detail": "invalid signature"})

    # Replay guard on the parsed timestamp INSIDE the payload (header auth
    # proves who; the payload timestamp proves when). Payloads must carry
    # {"key_id": ..., "timestamp": <unix seconds>, ...}.
    try:
        body = json.loads(raw)
        key_id = str(body.get("key_id") or "default")
        ts = int(body["timestamp"])
    except (ValueError, KeyError, TypeError):
        return JSONResponse(status_code=400, content={"detail": "payload needs key_id + timestamp"})

    ok, reason = _guard.check_and_record(key_id, ts)
    if not ok:
        return JSONResponse(status_code=409, content={"detail": reason})

    return {"accepted": True, "key_id": key_id}
