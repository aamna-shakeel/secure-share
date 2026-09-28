# Authorization Matrix

All checks are server-side. Buttons are usability affordances only. An unrelated or under-privileged authenticated actor receives `404` for object routes to reduce object-existence disclosure; an unauthenticated protected call receives `401`.

| Operation | Owner | Active shared user | Unrelated user | Unauthenticated |
|---|---:|---:|---:|---:|
| View document metadata | Yes | Yes | No | No |
| Download document | Yes | Yes | No | No |
| List accessible document | Yes | Yes | No | No |
| Delete document | Yes | No | No | No |
| Create/list/revoke user shares | Yes | No | No | No |
| Create/list/revoke public links | Yes | No | No | No |
| Public-link download | link not required | link not required | link not required | Valid link only |
| Revoked/expired/invalid public link | No | No | No | No |

## Enforcement map

- `get_document_for_view`: document owner or active `DocumentShare`; used by metadata and protected download.
- `get_owned_document`: exact document and actor ownership; used independently by delete and every share/link administration endpoint.
- `GET /documents`: SQL query returns only owned documents or documents with an active share for the actor.
- `GET /shared-with-me`: joins only active shares for the actor.
- `GET /shared/{token}`: separate capability path, constrained to download, with token HMAC, expiry, and revocation checks.

Revocation takes effect on the next server request. It cannot retract a file already downloaded.
