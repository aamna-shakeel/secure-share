from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

PASSWORD = "CorrectHorse9!"


@pytest.fixture
def app(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        session_secret="test-secret-that-is-long-and-unique",
        app_env="test",
        storage_dir=tmp_path / "storage",
        max_upload_bytes=128,
        cookie_secure=False,
        login_rate_limit=5,
        register_rate_limit=5,
        public_link_rate_limit=10,
        rate_limit_window_seconds=60,
    )
    return create_app(settings, create_schema=True)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def csrf_headers(client: TestClient) -> dict[str, str]:
    response = client.get("/auth/csrf")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def register(client: TestClient, email: str, password: str = PASSWORD) -> dict:
    response = client.post(
        "/auth/register",
        headers=csrf_headers(client),
        json={"email": email, "password": password, "password_confirmation": password},
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client: TestClient, email: str, password: str = PASSWORD) -> dict[str, str]:
    headers = csrf_headers(client)
    response = client.post("/auth/login", headers=headers, json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.headers["X-CSRF-Token"]}


def authenticated_client(app, email: str) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    client.__enter__()
    register(client, email)
    headers = login(client, email)
    return client, headers


def upload_txt(client: TestClient, headers: dict[str, str], filename: str = "notes.txt", content: bytes = b"private notes") -> dict:
    response = client.post("/documents", headers=headers, files={"file": (filename, content, "text/plain")})
    assert response.status_code == 201, response.text
    return response.json()
