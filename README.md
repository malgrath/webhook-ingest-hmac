# webhook-ingest-hmac

An HMAC-verified webhook ingest service. FastAPI + Pydantic-free core:
signature verification, replay protection, and fail-closed error paths,
with the security logic in pure, trivially-testable modules.

**Clean-room statement:** this codebase was written from scratch for this
repository. It is not derived from, translated from, or copied from any
private codebase. The git history *is* the complete history.

## The security model

1. **Authenticate the sender** — HMAC-SHA256 over the exact raw request
   bytes (`X-Signature-256: sha256=<hex>`), compared with
   `hmac.compare_digest` (constant-time). Malformed headers fail closed.
2. **Authenticate the moment** — the payload carries a unix timestamp; a
   sliding ±300 s window bounds message age. A valid signature proves *who*,
   not *when*; capture-and-replay of a signed request dies here.
3. **Dedupe within the window** — per-key seen-timestamp set. A replay of a
   genuine signed request inside the window hits the dedupe (409), outside
   it hits the age bound.
4. **Uniform errors** — 401 (bad signature), 400 (payload shape), 409
   (replay/stale). No signing oracle: the `/signature-for` helper exists
   only when no secret is configured.

Honest scope note: the replay guard is in-process. Multi-worker deployments
need a shared store (e.g. Redis SETNX); this repo prefers stating that over
pretending a dict is distributed.

## Quickstart

```bash
pip install -e ".[dev]"
export WEBHOOK_SECRET=dev-secret
uvicorn webhook_ingest.app:app --port 8000
```

Sign a request the way a sender would:

```bash
BODY='{"key_id":"k1","timestamp":'$(date +%s)'}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -hex | sed 's/^.* //')"
curl -s -X POST http://127.0.0.1:8000/ingest \
  -H "X-Signature-256: $SIG" -H 'Content-Type: application/json' \
  -d "$BODY"
```

## Layout

```
src/webhook_ingest/
├── verify.py   pure HMAC verification (constant-time, fail-closed)
├── store.py    replay guard (per-key sliding window)
└── app.py      FastAPI wiring (raw-body verification, uniform errors)
tests/          pytest — pure-layer + ASGI end-to-end, no network
Dockerfile      multi-stage, non-root, healthcheck
```

## Verification

```bash
pytest -q
```

## License

MIT
