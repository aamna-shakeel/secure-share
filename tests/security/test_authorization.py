from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import login, register, upload_txt


def test_unauthenticated_cannot_access_document(app):
    owner = TestClient(app)
    stranger = TestClient(app)
    owner.__enter__()
    stranger.__enter__()
    try:
        register(owner, "owner@example.com")
        headers = login(owner, "owner@example.com")
        document = upload_txt(owner, headers)
        assert stranger.get(f"/documents/{document['id']}").status_code == 401
        assert stranger.get(f"/documents/{document['id']}/download").status_code == 401
    finally:
        owner.__exit__(None, None, None)
        stranger.__exit__(None, None, None)


def test_unrelated_user_idor_is_denied_for_view_download_and_owner_actions(app):
    owner = TestClient(app)
    attacker = TestClient(app)
    owner.__enter__()
    attacker.__enter__()
    try:
        register(owner, "owner@example.com")
        owner_headers = login(owner, "owner@example.com")
        register(attacker, "attacker@example.com")
        attacker_headers = login(attacker, "attacker@example.com")
        document = upload_txt(owner, owner_headers)
        doc_id = document["id"]
        assert attacker.get(f"/documents/{doc_id}").status_code == 404
        assert attacker.get(f"/documents/{doc_id}/download").status_code == 404
        assert attacker.delete(f"/documents/{doc_id}", headers=attacker_headers).status_code == 404
        assert (
            attacker.post(f"/documents/{doc_id}/shares", headers=attacker_headers, json={"email": "owner@example.com"}).status_code == 404
        )
        assert attacker.get(f"/documents/{doc_id}/shares").status_code == 404
        assert attacker.post(f"/documents/{doc_id}/links", headers=attacker_headers, json={"expires_in_seconds": None}).status_code == 404
        assert attacker.get(f"/documents/{doc_id}/links").status_code == 404
        assert attacker.get("/documents").json() == []
    finally:
        owner.__exit__(None, None, None)
        attacker.__exit__(None, None, None)


def test_shared_user_has_read_only_access_and_cannot_revoke(app):
    owner = TestClient(app)
    shared = TestClient(app)
    owner.__enter__()
    shared.__enter__()
    try:
        register(owner, "owner@example.com")
        owner_headers = login(owner, "owner@example.com")
        register(shared, "shared@example.com")
        shared_headers = login(shared, "shared@example.com")
        document = upload_txt(owner, owner_headers)
        doc_id = document["id"]
        share = owner.post(f"/documents/{doc_id}/shares", headers=owner_headers, json={"email": "shared@example.com"}).json()
        assert shared.get(f"/documents/{doc_id}").json()["access"] == "shared"
        assert shared.get(f"/documents/{doc_id}/download").status_code == 200
        assert shared.delete(f"/documents/{doc_id}", headers=shared_headers).status_code == 404
        assert shared.post(f"/documents/{doc_id}/shares", headers=shared_headers, json={"email": "owner@example.com"}).status_code == 404
        assert shared.delete(f"/documents/{doc_id}/shares/{share['id']}", headers=shared_headers).status_code == 404
        assert shared.post(f"/documents/{doc_id}/links", headers=shared_headers, json={"expires_in_seconds": None}).status_code == 404
        assert shared.delete(f"/documents/{doc_id}/links/999", headers=shared_headers).status_code == 404
    finally:
        owner.__exit__(None, None, None)
        shared.__exit__(None, None, None)
