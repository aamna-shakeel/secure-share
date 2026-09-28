from __future__ import annotations

import hashlib
import hmac
import io
import re
import secrets
import time
import urllib.parse
import zipfile
from collections import defaultdict, deque
from pathlib import Path, PurePath

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_password_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,128}$", re.DOTALL)
ALLOWED_TYPES = {
    ".pdf": {"application/pdf"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "application/csv", "text/plain"},
}


class FileValidationError(ValueError):
    pass


def validate_password(password: str) -> None:
    if not PASSWORD_RE.match(password):
        raise ValueError("password must be 12-128 characters and include upper, lower, and numeric characters")


def hash_password(password: str) -> str:
    validate_password(password)
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str, secret: str) -> str:
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def generate_csrf_token(secret: str, binding: str = "anonymous") -> str:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    payload = f"{timestamp}.{nonce}"
    signature = hash_token(f"{payload}.{binding}", secret)
    return f"{payload}.{signature}"


def validate_csrf_token(token: str, secret: str, max_age_seconds: int, binding: str = "anonymous") -> bool:
    try:
        timestamp, nonce, supplied = token.split(".", 2)
        payload = f"{timestamp}.{nonce}"
        age = int(time.time()) - int(timestamp)
        expected = hash_token(f"{payload}.{binding}", secret)
        return 0 <= age <= max_age_seconds and hmac.compare_digest(supplied, expected)
    except (TypeError, ValueError):
        return False


def validate_filename(filename: str) -> str:
    if not filename or len(filename) > 255 or "\x00" in filename:
        raise FileValidationError("invalid filename")
    decoded = filename
    for _ in range(3):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if any(ord(ch) < 32 for ch in decoded) or "/" in decoded or "\\" in decoded:
        raise FileValidationError("filename must not contain path components")
    if PurePath(decoded).is_absolute() or decoded in {".", ".."} or PurePath(decoded).name != decoded:
        raise FileValidationError("invalid filename")
    extension = Path(decoded).suffix.lower()
    if extension not in ALLOWED_TYPES:
        raise FileValidationError("unsupported file extension")
    return extension


def validate_file(filename: str, declared_content_type: str | None, data: bytes) -> str:
    extension = validate_filename(filename)
    declared = (declared_content_type or "").split(";", 1)[0].strip().lower()
    if declared not in ALLOWED_TYPES[extension]:
        raise FileValidationError("content type does not match the allowed type")
    if not data:
        raise FileValidationError("empty files are not allowed")
    if extension == ".pdf" and not data.startswith(b"%PDF-"):
        raise FileValidationError("invalid PDF signature")
    if extension == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
                if "[Content_Types].xml" not in names or not any(name.startswith("word/") for name in names):
                    raise FileValidationError("invalid DOCX structure")
        except (zipfile.BadZipFile, RuntimeError) as exc:
            raise FileValidationError("invalid DOCX structure") from exc
    if extension in {".txt", ".csv"}:
        if b"\x00" in data:
            raise FileValidationError("text files must not contain NUL bytes")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileValidationError("text files must be UTF-8") from exc
    return declared


class InMemoryRateLimiter:
    """Simple process-local fixed-window limiter; intentionally testable and not distributed."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        events = self._events[key]
        while events and events[0] <= now - window_seconds:
            events.popleft()
        if len(events) >= limit:
            return False
        events.append(now)
        return True

    def clear(self) -> None:
        self._events.clear()
