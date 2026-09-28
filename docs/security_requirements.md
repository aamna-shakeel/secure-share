# Security Requirements and Traceability

Evidence below refers to tests actually executed locally on SQLite on 2026-09-28. OWASP ASVS **5.0.0** is a reference framework only; no compliance/certification claim is made.

| ID | Requirement | Implementation | Executed evidence / limitation |
|---|---|---|---|
| SR-01 | Authenticate protected operations | `get_current_user` dependency | unauthenticated authorization tests passed |
| SR-02 | Authorize every resource operation | owner/view helpers called by each ID route | owner/shared/unrelated matrix tests passed |
| SR-03 | Deny by default | no helper match returns 404 + audit | IDOR tests passed |
| SR-04 | Owner-only administration | `get_owned_document` | delete/share/link denial tests passed |
| SR-05 | Explicit shared access only | active `DocumentShare` existence check | share workflow passed |
| SR-06 | Shared users cannot administer | owner checks independent of UI | shared-user abuse test passed |
| SR-07 | Unrelated users denied | scoped list query and per-object checks | unrelated-user IDOR test passed |
| SR-08 | Unpredictable session IDs | `secrets.token_urlsafe(32)` | token unit test passed |
| SR-09 | No raw session in DB | HMAC-SHA-256 with app secret | persistence integration assertion passed |
| SR-10 | Expiry/revocation | timestamp/revocation checks and logout | session tests passed |
| SR-11 | Password hashing | Argon2id m=19456,t=2,p=1 | hash/verify tests passed |
| SR-12 | Server file validation | decoded name, extension, MIME and structure/signature | file abuse tests passed; no malware scanner |
| SR-13 | Generated storage IDs | UUID4 hex key | generated-key test passed |
| SR-14 | Traversal prevention | fixed root plus rejected separators/absolute/encoded traversal | traversal parameters passed |
| SR-15 | File-size cap | bounded read at configured maximum | oversized test passed; body may spool before handler |
| SR-16 | Security headers | middleware CSP/nosniff/frame/referrer/no-store | header test passed |
| SR-17 | CSRF defense | session-bound HMAC double-submit/header check | missing/invalid/valid tests passed |
| SR-18 | Abuse limiting | in-memory registration/login/public-link limiter | login limiter test passed; not distributed |
| SR-19 | Minimize sensitive exposure | response models, generic auth errors, token-safe audit | response/persistence checks passed; operator logging matters |
| SR-20 | Parameterized database operations | SQLAlchemy 2.x expression API | code/lint review; no SQL-injection scanner |
| SR-21 | Auditable security events | `AuditEvent` and central helper | auth/document audit assertions passed |

See `tests/`, `docs/testing.md`, and `research/security_evaluation.md` for commands and result boundaries.
