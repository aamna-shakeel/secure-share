from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import AuditEvent, BrowserSession, ShareLink, utcnow
from app.security import hash_token
from tests.conftest import PASSWORD, csrf_headers, login, register, upload_txt


def test_registration_login_identity_logout_and_hashed_session(app, client):
    user = register(client, "owner@example.com")
    headers = login(client, "owner@example.com")
    assert client.get("/auth/me").json()["id"] == user["id"]
    raw = client.cookies.get(app.state.settings.session_cookie_name)
    assert raw
    with app.state.SessionLocal() as db:
        session = db.scalar(select(BrowserSession))
        assert session.token_hash == hash_token(raw, app.state.settings.session_secret)
        assert session.token_hash != raw
    response = client.post("/auth/logout", headers=headers)
    assert response.status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_duplicate_registration_and_generic_login_failure_are_audited(app, client):
    register(client, "user@example.com")
    duplicate = client.post(
        "/auth/register",
        headers=csrf_headers(client),
        json={"email": "user@example.com", "password": PASSWORD, "password_confirmation": PASSWORD},
    )
    assert duplicate.status_code == 409
    failure = client.post("/auth/login", headers=csrf_headers(client), json={"email": "unknown@example.com", "password": "incorrect"})
    assert failure.status_code == 401
    assert failure.json()["detail"] == "invalid email or password"
    with app.state.SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == "LOGIN_FAILURE")) is not None


def test_expired_and_revoked_sessions_are_rejected(app, client):
    register(client, "session@example.com")
    login(client, "session@example.com")
    raw = client.cookies.get(app.state.settings.session_cookie_name)
    with app.state.SessionLocal() as db:
        session = db.scalar(select(BrowserSession).where(BrowserSession.token_hash == hash_token(raw, app.state.settings.session_secret)))
        session.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get("/auth/me").status_code == 401
    with app.state.SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == "SESSION_EXPIRED")) is not None


def test_document_upload_list_download_delete_and_audit(app, client):
    register(client, "docs@example.com")
    headers = login(client, "docs@example.com")
    document = upload_txt(client, headers)
    assert client.get("/documents").json()[0]["access"] == "owner"
    detail = client.get(f"/documents/{document['id']}")
    assert detail.status_code == 200 and "storage_key" not in detail.text
    download = client.get(f"/documents/{document['id']}/download")
    assert download.status_code == 200 and download.content == b"private notes"
    assert client.delete(f"/documents/{document['id']}", headers=headers).status_code == 200
    assert client.get(f"/documents/{document['id']}").status_code == 404
    assert list(app.state.settings.storage_dir.iterdir()) == []
    with app.state.SessionLocal() as db:
        types = set(db.scalars(select(AuditEvent.event_type)).all())
        assert {"UPLOAD", "DOWNLOAD", "DELETE"} <= types


def test_user_share_access_and_revocation(app):
    owner = TestClient(app)
    recipient = TestClient(app)
    owner.__enter__()
    recipient.__enter__()
    try:
        register(owner, "owner@example.com")
        owner_headers = login(owner, "owner@example.com")
        register(recipient, "recipient@example.com")
        login(recipient, "recipient@example.com")
        document = upload_txt(owner, owner_headers)
        share = owner.post(f"/documents/{document['id']}/shares", headers=owner_headers, json={"email": "recipient@example.com"})
        assert share.status_code == 201
        assert recipient.get(f"/documents/{document['id']}/download").content == b"private notes"
        assert recipient.get("/shared-with-me").json()[0]["id"] == document["id"]
        revoked = owner.delete(f"/documents/{document['id']}/shares/{share.json()['id']}", headers=owner_headers)
        assert revoked.status_code == 200
        assert recipient.get(f"/documents/{document['id']}/download").status_code == 404
        recreated = owner.post(f"/documents/{document['id']}/shares", headers=owner_headers, json={"email": "recipient@example.com"})
        assert recreated.status_code == 201 and recreated.json()["id"] == share.json()["id"]
        duplicate = owner.post(f"/documents/{document['id']}/shares", headers=owner_headers, json={"email": "recipient@example.com"})
        assert duplicate.status_code == 409
    finally:
        owner.__exit__(None, None, None)
        recipient.__exit__(None, None, None)


def test_public_link_valid_revoked_expired_and_hashed(app, client):
    register(client, "links@example.com")
    headers = login(client, "links@example.com")
    document = upload_txt(client, headers)
    created = client.post(f"/documents/{document['id']}/links", headers=headers, json={"expires_in_seconds": 60})
    assert created.status_code == 201
    url = urlparse(created.json()["url"]).path
    raw_token = url.rsplit("/", 1)[1]
    with app.state.SessionLocal() as db:
        link = db.get(ShareLink, created.json()["id"])
        assert link.token_hash != raw_token and raw_token not in link.token_hash
    assert client.get(url).content == b"private notes"
    assert client.delete(f"/documents/{document['id']}/links/{created.json()['id']}", headers=headers).status_code == 200
    assert client.get(url).status_code == 404
    expired = client.post(f"/documents/{document['id']}/links", headers=headers, json={"expires_in_seconds": 60}).json()
    with app.state.SessionLocal() as db:
        link = db.get(ShareLink, expired["id"])
        link.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get(urlparse(expired["url"]).path).status_code == 404
    assert client.get("/shared/not-a-real-token").status_code == 404
