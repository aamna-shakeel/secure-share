# Security Design

## Passwords and authentication

Passwords must be 12–128 characters with uppercase, lowercase, and a number. They are stored with Argon2id (`m=19456`, `t=2`, `p=1`, random salt). Login errors are generic. Successful and failed attempts are audited without password data.

## Sessions and cookies

A 32-byte CSPRNG value is the browser session token. The database stores only `HMAC-SHA-256(SESSION_SECRET, token)`, user, creation/expiry/revocation, and last-seen timestamps. Cookies are `HttpOnly`, `SameSite=Strict`, path `/`, and `Secure` by default in production. Logout revokes the row before deleting the cookie. Tokens never enter URLs or audit metadata.

## CSRF

Every `POST`, `PUT`, `PATCH`, and `DELETE` requires a token in both the readable CSRF cookie and `X-CSRF-Token`. The token contains a timestamp and random nonce with an HMAC. Before login it is bound to an anonymous context; login rotates it to a signature bound to the server-side session-token HMAC. Logout rotates back to anonymous. Validation checks both copies in constant time, signature, age, and current session binding. GET routes do not change authorization/business state (download auditing is incidental). SameSite is defense in depth, not the sole control.

## Authorization

Authentication and authorization are separate. Central helpers grant either owner+share read access or owner-only administration. Every route containing a document/share/link identifier performs a fresh database-bound check; nested IDs must belong to the authorized parent. Lists are server-filtered. Denials are audited where an authenticated object actor exists.

## Files

The upload handler reads at most configured limit + 1, rejects empty/oversized data, repeatedly URL-decodes names, rejects paths/separators/control characters, and allowlists extensions/MIME. It validates PDF magic, DOCX ZIP structure, and UTF-8/NUL-free text. A UUID4 hex key—not the original name—is written exclusively under the app-controlled directory (`0700`; file `0600`). The original name is metadata and a safe attachment name. Database failure removes the file. Delete uses quarantine/restore around the database transaction.

These checks are not malware analysis, CDR, or proof of benign content.

## Sharing and public links

One document/recipient row avoids duplicate active permissions; revocation is checked per request. Public links use independent 32-byte random tokens and persist only HMACs. The raw URL is returned only when created. Expiry and revocation are enforced per download, which confers no owner operation.

## Abuse controls and headers

Registration, login, and public-link access use a fixed-window in-memory limiter keyed by direct client IP (login also uses a truncated email hash). It is testable but process-local, reset on restart, and unsuitable as the only control across replicas. Responses set CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

## Audit/error/secrets/database

Audit events use allowlisted structured metadata and exclude passwords, file bytes, raw sessions, and raw links. Docker disables Uvicorn access logs because link tokens occur in paths. Public errors do not return tracebacks, SQL, filesystem paths, or secrets. SQLAlchemy expressions bind database values. Configuration comes from environment; `.env`, databases, logs, and storage content are ignored.

Audit data is not cryptographically tamper-evident and no external sink is included. Operators must configure TLS, proxy logging/redaction, database least privilege, backups, permissions, monitoring, and secret rotation.

## References

- [OWASP ASVS 5.0.0](https://owasp.org/projects/asvs) — reference framework, not a certification claim.
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
