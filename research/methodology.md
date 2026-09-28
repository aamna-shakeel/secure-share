# Evaluation Methodology

## Research question

> How effectively does the server-side authorization model prevent defined object-level access-control attacks in a document-sharing web application?

## Design

A controlled pytest suite creates independent owner, shared-user, unrelated-user, and unauthenticated clients against a fresh SQLite database. The owner uploads a known file. Tests manipulate sequential document/share/link IDs and call endpoints directly, without trusting UI restrictions. Each scenario has an expected HTTP status and, where material, verifies bytes, database state, audit state, or private-storage state.

## Attacker roles and scenarios

| Role | Controlled actions |
|---|---|
| Unauthenticated | metadata/download without a session; invalid session; public token guessing |
| Unrelated authenticated | direct view/download/delete; share and link administration by guessed document ID |
| Active shared user | allowed metadata/download; attempted delete/share/link/revoke operations |
| Holder of public link | valid download; reuse after revocation/expiry; invalid token |
| Malicious uploader | extension/MIME/signature mismatch, traversal encoding, absolute path, oversized data |
| Cross-site/automated actor | missing/invalid CSRF; repeated login attempts |

## Outcome rule

A scenario passes only when the response matches the designed permission/failure behavior and does not produce forbidden state. The suite itself is the executable oracle. Results are recorded only after actual execution. Assertions are not a proof for unenumerated inputs.

## Reproduction

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest tests/security -q
pytest -q
```

## Internal and external validity

Isolation improves reproducibility but differs from a networked PostgreSQL/TLS deployment. TestClient does not model all browser/proxy behavior. The scenarios cover defined object operations and selected file/session/web controls; they do not establish absence of vulnerabilities, cryptographic implementation proof, malware safety, availability under load, dependency safety, or operational security.
