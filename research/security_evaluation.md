# Executed Security Evaluation

**Execution date:** 2026-09-28  
**Environment:** Python 3.11, FastAPI TestClient, SQLAlchemy with temporary SQLite and private temporary directories.  
**Commands:** `pytest tests/security -q` → **15 passed, 0 failed, 0 skipped** in 1.82 s; definitive `pytest -q` → **38 passed, 0 failed, 0 skipped** in 2.90 s. Both followed the session-bound CSRF refinement.

| Objective | Endpoint/input | Attacker | Expected | Actual executed result | Control | Outcome |
|---|---|---|---|---|---|---|
| Read protected object without login | document metadata/download ID | unauthenticated | 401 | 401 | session dependency | Pass |
| IDOR read/download | another owner's document ID | unrelated account | concealed denial | 404 | `get_document_for_view` | Pass |
| IDOR delete | another owner's document ID | unrelated account | concealed denial | 404 | `get_owned_document` | Pass |
| Administer shares/links | another owner's document ID | unrelated account | concealed denial | 404 across create/list operations | owner helper | Pass |
| Read explicit share | shared document ID | active shared user | 200 | metadata/download 200 | active-share predicate | Pass |
| Escalate shared access | delete/share/revoke/link operations | shared user | denied | 404 across tested owner operations | owner helper | Pass |
| Reuse revoked user share | download after revocation | former shared user | denied | 404 | per-request revocation check | Pass |
| Guess public token | invented token | public | denied | 404 | token HMAC lookup | Pass |
| Reuse revoked/expired link | valid URL after state change | public | denied | 404 for both | revocation/expiry checks | Pass |
| Use valid link | fresh URL | public | file only | 200 with expected bytes | capability-limited route | Pass |
| Traverse storage path | `../`, encoded, absolute names | malicious uploader | reject/no artifact | 422 and no document/file | filename validation + generated key | Pass |
| Bypass type/size policy | bad extension/MIME/signature, 129-byte test cap | malicious uploader | reject | 422/413 and no document | layered validation/bounded read | Pass |
| Forge CSRF | absent/invalid token | browser attacker | reject | 403; valid token accepted | bound signed double-submit | Pass |
| Abuse login repeatedly | third request at test limit two | automated actor | throttle | 429 | process-local limiter | Pass |
| Use invented session | random cookie | unauthenticated | reject | 401 | HMAC session lookup | Pass |
| Omit security headers | normal/error responses | passive attack precondition | headers present | all asserted headers present | response middleware | Pass |

## Interpretation

All defined automated scenarios produced their expected outcomes. This supports the narrow conclusion that the implemented server-side checks blocked the tested object-level access attempts. It does not establish security outside the scenario set or under a production deployment.

## Limitations

No live PostgreSQL, Docker, TLS/reverse proxy, distributed limiter, concurrency/load, malware, SAST/DAST, dependency vulnerability, real-browser, or independent penetration test was executed. Revocation cannot retract already downloaded copies. The test suite uses known IDs rather than a high-volume discovery campaign because authorization—not ID secrecy—is the control under study.
