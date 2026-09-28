# API Notes

Interactive OpenAPI documentation is served at `/docs`. Protected calls use the `secureshare_session` HttpOnly cookie. Obtain a CSRF value with `GET /auth/csrf`; for every POST/PUT/PATCH/DELETE send that value in both its cookie and `X-CSRF-Token`. Login rotates the CSRF token and returns the replacement in the response header.

The major routes are `/auth/*`, `/documents`, `/documents/{id}`, `/documents/{id}/download`, nested `/shares` and `/links`, `/shared-with-me`, and public `GET /shared/{token}`. Link creation returns its raw URL once; link listings never return tokens. `storage_key`, password hashes, session tokens, token hashes, and internal paths are absent from response schemas.

Use Uvicorn with `--no-access-log`, or configure upstream redaction, because a public token necessarily appears in the public download URL.
