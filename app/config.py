from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Settings:
    database_url: str = "sqlite:///./secureshare.db"
    session_secret: str = "development-only-change-me"
    app_env: str = "development"
    storage_dir: Path = Path("./storage")
    session_cookie_name: str = "secureshare_session"
    csrf_cookie_name: str = "secureshare_csrf"
    session_ttl_seconds: int = 8 * 60 * 60
    csrf_ttl_seconds: int = 8 * 60 * 60
    max_upload_bytes: int = 10 * 1024 * 1024
    cookie_secure: bool = False
    login_rate_limit: int = 5
    register_rate_limit: int = 5
    public_link_rate_limit: int = 30
    rate_limit_window_seconds: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.getenv("APP_ENV", "development")
        secret = os.getenv("SESSION_SECRET", "development-only-change-me")
        if env == "production" and secret == "development-only-change-me":
            raise RuntimeError("SESSION_SECRET must be configured in production")
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./secureshare.db"),
            session_secret=secret,
            app_env=env,
            storage_dir=Path(os.getenv("STORAGE_DIR", "./storage")),
            session_ttl_seconds=int(os.getenv("SESSION_TTL_SECONDS", str(8 * 60 * 60))),
            csrf_ttl_seconds=int(os.getenv("CSRF_TTL_SECONDS", str(8 * 60 * 60))),
            max_upload_bytes=int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024))),
            cookie_secure=os.getenv("COOKIE_SECURE", "true" if env == "production" else "false").lower() == "true",
            login_rate_limit=int(os.getenv("LOGIN_RATE_LIMIT", "5")),
            register_rate_limit=int(os.getenv("REGISTER_RATE_LIMIT", "5")),
            public_link_rate_limit=int(os.getenv("PUBLIC_LINK_RATE_LIMIT", "30")),
            rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
        )
