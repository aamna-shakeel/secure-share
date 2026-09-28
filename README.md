# SecureShare

SecureShare is a focused document-sharing web application that examines:

> How effectively does a server-side authorization model prevent defined object-level access-control attacks in a document-sharing web application?

It implements and tests a defined control set. **It is not presented as universally secure, production-ready, ASVS-certified, or penetration-test certified.**

## Features

- Email registration with Argon2id password hashes
- Opaque, hashed, expiring, revocable server-side sessions
- Session-bound signed double-submit CSRF defense
- Private random-key storage for validated PDF, DOCX, UTF-8 TXT, and CSV files
- Owner/shared-user authorization at every resource endpoint
- Owner-only delete, user-share administration, and public-link administration
- Expiring/revocable public links; only token HMACs are persisted
- Security audit events, process-local sensitive-route rate limits, and security headers
- Functional same-origin HTML/CSS/JavaScript interface and OpenAPI documentation

## Architecture

FastAPI serves the browser client and API. SQLAlchemy 2.x targets PostgreSQL in Compose; tests use SQLite. Files stay outside the static web root under generated 128-bit hexadecimal keys. Reusable authorization helpers check ownership or an active share **before** reading files. See [architecture](docs/architecture.md), [security](docs/security.md), and the [authorization matrix](docs/authorization_matrix.md).

```text
app/api/            HTTP routes
app/*.py            models, persistence, security, authorization
app/static/         browser client
migrations/         Alembic schema
scripts/            database-readiness helper
tests/{unit,integration,security}/
docs/               engineering/security documentation
research/           methodology and executed evaluation
storage/            ignored private runtime data
```

## Local setup with SQLite

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL='sqlite:///./secureshare.db'
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export STORAGE_DIR='./storage'
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Open <http://127.0.0.1:8000/>; the OpenAPI specification is available at `/openapi.json`. The interactive Swagger UI at `/docs` may be blocked by the application's strict Content Security Policy because its development assets are loaded from an external CDN. Keep the access log disabled because public-link tokens are path parameters.

## Docker Compose with PostgreSQL

```bash
cp .env.example .env
# Set strong SESSION_SECRET and POSTGRES_PASSWORD values in .env.
docker compose up --build
docker compose down
docker compose down -v  # also deletes development data volumes
```

A database health check and `scripts/wait_for_db.py` gate migration/application startup. Docker was unavailable in the implementation environment, so Compose and live PostgreSQL startup were **not executed** there.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy URL | `sqlite:///./secureshare.db` |
| `SESSION_SECRET` | HMAC key | unsafe dev placeholder; rejected in production |
| `APP_ENV` | environment | `development` |
| `STORAGE_DIR` | non-public file directory | `./storage` |
| `COOKIE_SECURE` | HTTPS-only cookies | true by default in production |
| `SESSION_TTL_SECONDS` | session lifetime | 28800 |
| `CSRF_TTL_SECONDS` | CSRF lifetime | 28800 |
| `MAX_UPLOAD_BYTES` | upload cap | 10485760 |
| rate-limit variables | per-window request limits | see `.env.example` |

Terminate TLS before the app and keep `COOKIE_SECURE=true` in deployment.

## Migrations and checks

```bash
alembic upgrade head
alembic current
pytest -q
pytest tests/unit -q
pytest tests/integration -q
pytest tests/security -q
ruff format --check .
ruff check .
python -m compileall -q app migrations scripts
git diff --check
```

Latest actually executed results are in [testing.md](docs/testing.md) and [security_evaluation.md](research/security_evaluation.md).

## Security model

A document ID is a lookup input, never proof of authority. View/download needs ownership or an active recipient share. Administrative actions require ownership. A valid public token permits only its download route. Session/link tokens carry 256 random bits; the database receives only HMAC-SHA-256 values. CSRF tokens are signed, bound to the login-session hash, sent in a custom header, and reinforced by `SameSite=Strict`.

## Limitations and scope exclusions

- No malware scanner, CDR, quota, or at-rest file encryption. Structural checks do not prove content benign.
- In-memory per-process rate limits reset on restart and do not coordinate replicas.
- No account recovery, email verification, MFA, OAuth, JWT browser auth, admin UI, or editing.
- Direct peer IP is used; proxy forwarding headers are not interpreted.
- Audit events lack an external immutable sink and retention service.
- Public downloads remain a bandwidth/resource-exhaustion risk.
- Automated tests ran on SQLite. Docker and live PostgreSQL were unavailable.

## Evaluated status

The latest full local run passed **38/38** tests; separate runs passed 17 unit, 6 integration, and 15 security tests. This applies only to those scenarios and that environment, not to untested attacks or deployment configuration.

## License

[MIT](LICENSE)
