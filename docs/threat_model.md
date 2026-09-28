# Threat Model

## Scope and assets

Protected assets are credentials/password hashes, session state and tokens, document bytes/metadata, share permissions, public-link tokens, audit records, database contents, private storage, and application secrets.

## Actors

| Actor | Capability and objective |
|---|---|
| T1 unauthenticated attacker | Calls APIs, guesses IDs/tokens, tries protected resources |
| T2 malicious authenticated user | Uses a valid account to cross object/owner boundaries |
| T3 abusive request manipulator | Changes IDs, bodies, names, encodings, or bypasses UI |
| T4 automated attacker | Repeats login, registration, public-link, or download requests |
| T5 malicious uploader | Supplies traversal names, MIME mismatches, unsupported/oversized or malicious content |

## Attack surfaces and controls

| Surface/threat | Implemented mitigation | Residual risk |
|---|---|---|
| Password guessing | Argon2id, generic failure, per-process login limiting, audit | Distributed/slow attacks; no MFA |
| Session theft/guessing | 256-bit tokens, server-side HMAC rows, HttpOnly/SameSite/Secure-in-production, expiry/revocation | Client compromise, TLS/proxy misconfiguration |
| CSRF | Session-bound HMAC double-submit token, custom header, constant-time match, SameSite | Compromised same-origin script; sibling-domain/deployment configuration |
| IDOR/BOLA | Server-side owner/active-share checks on each object endpoint; 404 concealment | Authorization code regression outside tested routes |
| Share replay | Revocation checked at each access; unique recipient row | Already-downloaded copies cannot be revoked |
| Public-token guessing | 256-bit token, HMAC storage, expiry/revocation, rate limit | Token disclosure by recipient/browser/proxy; bandwidth abuse |
| Path traversal | repeated URL decode checks; reject separators/absolute paths; generated storage keys | Filesystem compromise outside application |
| Malicious files | allowlisted extensions/types, PDF signature, DOCX structure, UTF-8/NUL checks, size cap, attachment responses | No malware scan/CDR; polyglots/parser bugs |
| XSS/clickjacking/MIME | DOM `textContent`, CSP, frame denial, nosniff, attachment download | Dependencies/browser flaws; CSP is not a sanitizer |
| Sensitive logging | structured audit allowlist; raw tokens/passwords excluded; Docker disables URL access logs | Operator may enable proxy/access logs containing link URLs |
| Database injection | SQLAlchemy bound expressions | Dependency/driver defects, unsafe future code |
| Resource exhaustion | bounded upload and selected rate limits | Authenticated download/upload volume, memory buffering |

## Trust boundaries

Browser/API, public-link/API, API/database, and API/private-storage are separate trust boundaries. UI visibility is never a security boundary.

## Assumptions

Deployment supplies TLS, a high-entropy secret, restricted database credentials, a private durable storage mount, host patching, and backup/restore controls. These operational controls were not implemented by application code.

## Implemented versus planned

All controls in the tables are implemented for this scope. No unimplemented feature is presented as a control. Possible future operational hardening—not committed scope—includes distributed limiting, malware scanning/CDR, immutable audit export, object storage, quotas, and independent penetration testing.
