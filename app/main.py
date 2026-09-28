from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import auth, documents, sharing
from app.config import Settings
from app.db import Base, build_engine, build_session_factory
from app.security import InMemoryRateLimiter, hash_token, validate_csrf_token


def create_app(settings: Settings | None = None, *, create_schema: bool = False) -> FastAPI:
    settings = settings or Settings.from_env()
    storage_dir = settings.storage_dir.resolve()
    storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(storage_dir, 0o700)
    engine = build_engine(settings.database_url)
    # Private app-owned metadata avoids passing filesystem paths through user input.
    engine._secureshare_storage_dir = storage_dir  # type: ignore[attr-defined]
    if create_schema:
        Base.metadata.create_all(engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        engine.dispose()

    application = FastAPI(
        title="SecureShare",
        version="1.0.0",
        description="Security-focused document sharing with explicit server-side authorization.",
        lifespan=lifespan,
    )
    application.state.settings = settings
    application.state.engine = engine
    application.state.SessionLocal = build_session_factory(engine)
    application.state.rate_limiter = InMemoryRateLimiter()

    @application.middleware("http")
    async def csrf_and_security_headers(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            cookie = request.cookies.get(settings.csrf_cookie_name, "")
            header = request.headers.get("X-CSRF-Token", "")
            raw_session = request.cookies.get(settings.session_cookie_name)
            binding = hash_token(raw_session, settings.session_secret) if raw_session else "anonymous"
            if (
                not cookie
                or not header
                or not hmac.compare_digest(cookie, header)
                or not validate_csrf_token(header, settings.session_secret, settings.csrf_ttl_seconds, binding)
            ):
                response = JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    application.include_router(auth.router)
    application.include_router(documents.router)
    application.include_router(sharing.router)
    static_dir = Path(__file__).parent / "static"
    application.mount("/static", StaticFiles(directory=static_dir), name="static")

    @application.get("/", include_in_schema=False)
    def frontend() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    return application


app = create_app()
