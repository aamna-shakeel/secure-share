from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import Document
from tests.conftest import PASSWORD, csrf_headers, login, register


def test_csrf_missing_invalid_and_valid(client):
    payload = {"email": "csrf@example.com", "password": PASSWORD, "password_confirmation": PASSWORD}
    assert client.post("/auth/register", json=payload).status_code == 403
    assert client.post("/auth/register", headers={"X-CSRF-Token": "invalid"}, json=payload).status_code == 403
    assert client.post("/auth/register", headers=csrf_headers(client), json=payload).status_code == 201
    anonymous_headers = csrf_headers(client)
    login_response = client.post("/auth/login", headers=anonymous_headers, json={"email": "csrf@example.com", "password": PASSWORD})
    assert login_response.status_code == 200
    assert login_response.headers["X-CSRF-Token"] != anonymous_headers["X-CSRF-Token"]
    assert client.post("/documents", headers=anonymous_headers, files={"file": ("x.txt", b"x", "text/plain")}).status_code == 403
    bound_headers = {"X-CSRF-Token": login_response.headers["X-CSRF-Token"]}
    assert client.post("/documents", headers=bound_headers, files={"file": ("x.txt", b"x", "text/plain")}).status_code == 201


def test_security_headers_on_success_and_error(client):
    for response in (client.get("/health"), client.get("/documents")):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("filename", "content_type", "content", "expected"),
    [
        ("payload.exe", "application/octet-stream", b"MZ", 422),
        ("fake.pdf", "text/plain", b"%PDF-1.7", 422),
        ("fake.pdf", "application/pdf", b"not-a-pdf", 422),
        ("../escape.txt", "text/plain", b"text", 422),
        ("..%2Fescape.txt", "text/plain", b"text", 422),
        ("/tmp/escape.txt", "text/plain", b"text", 422),
        ("large.txt", "text/plain", b"x" * 129, 413),
    ],
)
def test_file_validation_abuse_cases(app, client, filename, content_type, content, expected):
    register(client, "files@example.com")
    headers = login(client, "files@example.com")
    response = client.post("/documents", headers=headers, files={"file": (filename, content, content_type)})
    assert response.status_code == expected
    with app.state.SessionLocal() as db:
        assert db.scalar(select(Document)) is None
    assert list(app.state.settings.storage_dir.iterdir()) == []


def test_generated_storage_key_is_not_filename_or_path(app, client):
    register(client, "safe@example.com")
    headers = login(client, "safe@example.com")
    response = client.post("/documents", headers=headers, files={"file": ("friendly.txt", b"hello", "text/plain")})
    assert response.status_code == 201
    with app.state.SessionLocal() as db:
        document = db.scalar(select(Document))
        assert document.storage_key != document.original_filename
        assert "/" not in document.storage_key and "\\" not in document.storage_key
        assert (app.state.settings.storage_dir / document.storage_key).is_file()


def test_login_rate_limit_eventually_blocks(client, app):
    app.state.settings.login_rate_limit = 2
    register(client, "rate@example.com")
    for _ in range(2):
        response = client.post("/auth/login", headers=csrf_headers(client), json={"email": "rate@example.com", "password": "wrong"})
        assert response.status_code == 401
    blocked = client.post("/auth/login", headers=csrf_headers(client), json={"email": "rate@example.com", "password": "wrong"})
    assert blocked.status_code == 429


def test_invalid_session_cookie_is_rejected(client, app):
    client.cookies.set(app.state.settings.session_cookie_name, "invented-session-token")
    assert client.get("/auth/me").status_code == 401
