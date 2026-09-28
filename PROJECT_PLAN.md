# SecureShare Project Plan

## Objectives and scope

Build the specified FastAPI/SQLAlchemy document-sharing application and evaluate defined object-level authorization attacks. In scope: registration, cookie sessions, private documents, user shares, public links, audit events, CSRF, rate limits, headers, frontend, migrations, Docker, tests, and research documentation. Scope exclusions in the master specification remain excluded.

## Milestones and status

| Milestone | Status | Evidence |
|---|---|---|
| Scaffolding/configuration | Complete | `app/`, environment config, dependencies |
| Schema/migrations | Implemented; SQLite migration executed | `models.py`, Alembic revision |
| Authentication/sessions | Complete in tested scope | auth integration tests |
| Authorization foundation | Complete in tested scope | centralized helpers and matrix tests |
| Documents/private storage | Complete in tested scope | integration and file-abuse tests |
| User shares/public links | Complete in tested scope | workflow, expiry/revocation tests |
| Web security/auditing | Complete in tested scope | CSRF/header/rate/audit tests |
| Frontend | Implemented; startup page checked | `app/static/` |
| Automated evaluation | 38-test full suite passed | 2026-09-28 local SQLite run |
| PostgreSQL/Compose runtime validation | Blocked | Docker/PostgreSQL unavailable in sandbox |
| Documentation/final audit | Complete; final checks recorded | `docs/`, `research/` |

## Architecture decisions

- **Opaque cookie session + database row:** supports server-side expiry and revocation; only an HMAC is stored.
- **Session-bound signed double-submit CSRF:** supports JSON/multipart frontend calls, pre-auth registration/login, and post-auth session binding.
- **Generated storage key:** original filename is metadata only; private files are never static assets.
- **Central owner/viewer helpers:** all object endpoints invoke explicit authorization and conceal unrelated objects with 404.
- **One share row per document/recipient:** a revoked row is reactivated instead of creating contradictory duplicates.
- **Audit record document IDs are not foreign keys:** document deletion preserves evidence without preventing deletion.
- **Process-local limiter:** intentionally small and testable; distributed deployment requires replacement.
- **Alembic:** application startup does not silently create schema; operators run migrations explicitly.

## Remaining limitations

No live PostgreSQL, Docker, proxy/TLS, multi-process rate-limit, malware scanning, external audit sink, load, browser automation, SAST/DAST, or third-party penetration test was executed. These are deployment/evaluation limitations, not claims that the features are safe by omission.
