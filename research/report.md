# SecureShare: Evaluating Server-Side Object Authorization

## 1. Abstract

SecureShare is a FastAPI document-sharing prototype built to evaluate whether explicit server-side authorization blocks a defined set of object-level access attacks. The implementation separates authentication from authorization, models ownership and revocable recipient shares, and constrains public links to document download. A controlled local run executed 38 tests; all passed their defined assertions. This result supports only the enumerated scenarios in the SQLite test environment and is not a general security or compliance claim.

## 2. Introduction

Document applications expose identifiers through routes and clients. If an implementation treats an identifier or hidden UI control as authority, authenticated users can cross account boundaries. SecureShare instead checks the actor and requested object at each operation, then tests those decisions directly.

## 3. Problem statement

The system must allow owners to manage content, shared users to read only granted content, unrelated users to receive no access, and anonymous users to download only through valid public capabilities. Revocation and expiry must be effective at the next request.

## 4. Research question

> How effectively does the server-side authorization model prevent defined object-level access-control attacks in a document-sharing web application?

Supporting questions address ID manipulation, shared-user escalation, revoked/expired permission replay, and whether automated tests detect violations.

## 5. System design

FastAPI routes use SQLAlchemy 2.x models for users, hashed browser sessions, documents, recipient shares, hashed public links, and audit events. Private files use generated keys outside the static root. Pydantic and layered file checks validate input. A same-origin JavaScript interface calls the same API. PostgreSQL is configured for deployment and Alembic owns schema creation; SQLite supports isolated tests.

## 6. Threat model

The actors are unauthenticated attackers, malicious authenticated users, request manipulators, automated attackers, and malicious uploaders. Protected assets include credentials, session/link capabilities, documents and metadata, permissions, audit evidence, database, storage, and secrets. Principal threats are IDOR/BOLA, privilege escalation, capability guessing/replay, session abuse, CSRF, traversal/type confusion, sensitive logging, and resource exhaustion.

## 7. Security controls

The design uses deny-by-default object helpers; owner/active-share query predicates; owner-only administration; 256-bit CSPRNG session/link values with only keyed HMACs persisted; Argon2id password storage; absolute session expiry/revocation; session-bound signed double-submit CSRF; file allowlists/signatures/size caps/generated paths; selected process-local rate limits; security response headers; and structured audit events. Controls follow selected ideas in OWASP guidance and ASVS 5.0.0 as a reference, without a certification claim.

## 8. Experimental methodology

Fresh temporary databases and storage directories isolate pytest scenarios. Multiple clients model owner, shared, unrelated, and anonymous roles. Tests call APIs directly and manipulate IDs. Expected outcomes are response codes plus relevant bytes and database/filesystem state. Security tests cover view/download/delete/share/link authorization, revoked permissions, invalid capabilities/sessions, CSRF, headers, rate limiting, and upload abuse.

## 9. Results

On 2026-09-28, the definitive `pytest -q` run completed **38 passed, 0 failed, 0 skipped** in 2.90 seconds. Separate runs completed 17 unit, 6 integration, and 15 security tests. The defined authorization attacks were denied; explicitly shared and valid-link downloads succeeded; revocation/expiry prevented subsequent access. Detailed scenario outcomes are in `security_evaluation.md`.

## 10. Discussion

The evidence is consistent with the central hypothesis for this bounded implementation: checking both actor and object on every route prevented tested identifier manipulation and horizontal/vertical escalation. Sequential IDs remained safe in the scenarios because secrecy was not the authorization control. Independent checks on nested share/link IDs prevented using a valid child identifier under an unauthorized document.

The strongest evidence comes from direct negative tests across multiple operations rather than UI behavior. However, passing tests also reflect the completeness of their oracle; they cannot detect omitted scenarios or deployment defects.

## 11. Limitations

The evaluation used SQLite/TestClient, not live PostgreSQL, Docker, TLS, a proxy, or multiple workers. There was no malware scanning, SAST/DAST, dependency vulnerability scan, fuzzing, sustained load/concurrency, fault injection, browser automation, or independent penetration test. Rate limiting is local and volatile. Audit records are not externally immutable. File validation cannot establish benign content. A revoked recipient may retain previously downloaded bytes.

## 12. Conclusion

For the explicitly modeled routes, roles, and manipulations, SecureShare's server-side object authorization produced the expected deny/permit decisions in the executed suite. The result is reproducible evidence for this scenario set, not evidence of universal security. Live PostgreSQL/deployment testing and broader adversarial assessment remain necessary before operational use.

## 13. References

1. OWASP Foundation. [Application Security Verification Standard 5.0.0](https://owasp.org/projects/asvs).
2. OWASP Cheat Sheet Series. [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
3. OWASP Cheat Sheet Series. [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
4. OWASP Cheat Sheet Series. [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
5. OWASP Cheat Sheet Series. [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
6. OWASP Cheat Sheet Series. [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
7. OWASP Cheat Sheet Series. [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
