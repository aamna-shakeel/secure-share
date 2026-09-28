from __future__ import annotations

import io
import zipfile

import pytest

from app.schemas import RegisterRequest
from app.security import (
    FileValidationError,
    InMemoryRateLimiter,
    generate_csrf_token,
    generate_token,
    hash_password,
    hash_token,
    validate_csrf_token,
    validate_file,
    validate_filename,
    validate_password,
    verify_password,
)


def test_password_policy_hash_and_verify():
    validate_password("A-longPassword9")
    encoded = hash_password("A-longPassword9")
    assert "A-longPassword9" not in encoded
    assert verify_password(encoded, "A-longPassword9")
    assert not verify_password(encoded, "wrong")


@pytest.mark.parametrize("password", ["short", "alllowercase123", "ALLUPPERCASE123", "NoNumbersHere!"])
def test_password_policy_rejects_weak_passwords(password):
    with pytest.raises(ValueError):
        validate_password(password)


def test_registration_confirmation_must_match():
    with pytest.raises(ValueError):
        RegisterRequest(email="person@example.com", password="CorrectHorse9!", password_confirmation="DifferentHorse9!")


def test_tokens_are_random_and_only_deterministic_hash_is_stored():
    one, two = generate_token(), generate_token()
    assert one != two and len(one) >= 40
    assert hash_token(one, "secret") == hash_token(one, "secret")
    assert one not in hash_token(one, "secret")
    assert hash_token(one, "secret") != hash_token(one, "other")


def test_csrf_signature_and_age(monkeypatch):
    monkeypatch.setattr("app.security.time.time", lambda: 1000)
    token = generate_csrf_token("secret")
    assert validate_csrf_token(token, "secret", 60)
    assert not validate_csrf_token(token + "x", "secret", 60)
    monkeypatch.setattr("app.security.time.time", lambda: 1061)
    assert not validate_csrf_token(token, "secret", 60)


@pytest.mark.parametrize("filename", ["../x.txt", "..%2Fx.txt", "%252e%252e%252fx.txt", "/tmp/x.txt", "folder\\x.txt", "bad.exe"])
def test_filename_rejects_traversal_and_unsupported_types(filename):
    with pytest.raises(FileValidationError):
        validate_filename(filename)


def test_file_validation_signatures_and_utf8():
    assert validate_file("report.pdf", "application/pdf", b"%PDF-1.7\n") == "application/pdf"
    assert validate_file("notes.txt", "text/plain; charset=utf-8", "hello".encode()) == "text/plain"
    with pytest.raises(FileValidationError):
        validate_file("report.pdf", "application/pdf", b"not pdf")
    with pytest.raises(FileValidationError):
        validate_file("notes.txt", "text/plain", b"bad\x00text")


def test_docx_structure_validation():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert validate_file("safe.docx", mime, output.getvalue()) == mime
    with pytest.raises(FileValidationError):
        validate_file("safe.docx", mime, b"PK-invalid")


def test_rate_limiter_is_bounded_and_resettable():
    limiter = InMemoryRateLimiter()
    assert limiter.check("key", 2, 60)
    assert limiter.check("key", 2, 60)
    assert not limiter.check("key", 2, 60)
    limiter.clear()
    assert limiter.check("key", 2, 60)
