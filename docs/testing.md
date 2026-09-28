# Testing

## Architecture

Each test receives a fresh FastAPI application, temporary SQLite database, and temporary private-storage directory. Helpers issue valid CSRF tokens and authenticate independent `TestClient` instances. Tests inspect both HTTP behavior and server-side database/filesystem state.

- `tests/unit/`: password policy/hash, token/HMAC, CSRF signature/age, filename and content validation, DOCX structure, rate limiter.
- `tests/integration/`: registration/login/logout, raw-token absence, expiry, documents, audit events, user-share lifecycle, public-link lifecycle.
- `tests/security/`: unauthenticated/unrelated/shared authorization, IDOR across operations, CSRF failure/success, headers, rate limiting, invalid sessions, upload abuse.

## Commands

```bash
pytest -q
pytest tests/unit -q
pytest tests/integration -q
pytest tests/security -q
ruff format --check .
ruff check .
python3 -m compileall -q app migrations scripts

# Migration round trip on disposable SQLite
TMP=$(mktemp -d)
DATABASE_URL="sqlite:///$TMP/test.db" alembic upgrade head
DATABASE_URL="sqlite:///$TMP/test.db" alembic downgrade base
rm -rf "$TMP"
```

## Actually executed results (2026-09-28)

| Command | Result |
|---|---|
| `pytest -q` | **38 passed, 0 failed, 0 skipped** in 2.90 s (definitive final run) |
| `pytest tests/unit -q` | **17 passed** in 0.12 s (earlier same implementation phase) |
| `pytest tests/integration -q` | **6 passed** in 0.94 s |
| `pytest tests/security -q` | **15 passed** in 1.82 s |
| `ruff format --check .` and `ruff check .` | passed in the definitive final check |
| SQLite Alembic upgrade + downgrade | passed |
| temporary SQLite migration + Uvicorn + `/health` + `/` smoke check | passed; health returned `{"status":"ok"}` |
| `docker compose config` | not run: Docker executable unavailable |
| live PostgreSQL tests | not run: PostgreSQL service unavailable |

The final full and separate suite runs followed the session-binding refinement. The full 38-test run is the authoritative behavioral result. No coverage measurement was run.

## Expected behavior

Security tests pass when attacks are **denied as specified**, not when an attack succeeds. A 404 is expected for authenticated unrelated/under-privileged object access, 401 for missing/invalid sessions, 403 for CSRF failure, 413 for size, 422 for invalid file metadata/content, and 429 after rate-limit exhaustion.

## Gaps

SQLite cannot validate PostgreSQL connection behavior, isolation differences, permissions, or deployment migrations. There was no real browser automation, concurrency/load test, fault injection at filesystem/database commit boundaries, dependency vulnerability scan, SAST/DAST, or penetration test.
