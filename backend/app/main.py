import os
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.api import auth, dashboard, devices, events, integrations, notifications, system
from app.api import scanner as scanner_api
from app.api.deps import require_user
from app.core.config import Config
from app.db.session import make_engine, make_session_factory
from app.discovery.adguard import AdGuardProvider
from app.discovery.arp_scan import ArpScanProvider
from app.discovery.neighbor import NeighborProvider
from app.discovery.services import MdnsProvider, SsdpProvider
from app.integrations.adguard import AdGuardClient
from app.notifications.email_provider import EmailProvider
from app.notifications.webhook import WebhookProvider
from app.services import notification_rules as rules
from app.services.crypto import SecretBox
from app.services.notifier import Notifier
from app.services.scanner import Scanner

MIGRATIONS_DIR = Path(__file__).parent / "db" / "migrations"
# The SPA ships no inline scripts and loads nothing from other origins. 'unsafe-inline' is for style
# attributes only (chart bar widths); scripts stay locked to same-origin files.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
)


def run_migrations(url: str, db_key: bytes | None = None) -> None:
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["url"] = url  # not set_main_option: configparser would mangle '%' in URLs
    cfg.attributes["db_key"] = db_key
    command.upgrade(cfg, "head")


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config()
    os.umask(0o077)  # the DB (password hash, encrypted secrets) and secret key are owner-only however we were launched
    config.data_dir.mkdir(parents=True, exist_ok=True)
    secret_key = config.resolve_secret_key()
    db_key = config.db_key(secret_key)  # raises if encryption is on and the key sits in the data dir
    engine = make_engine(config.db_url, db_key)
    if db_key:  # fail now, with a clear message, rather than on the first request
        try:
            engine.connect().close()
        except Exception as e:  # sqlcipher raises its own DatabaseError type
            raise RuntimeError("cannot open the database: wrong key, or the file is not encrypted (python -m app encrypt-db)") from e

    session_factory = make_session_factory(engine)
    box = SecretBox(secret_key)
    # Providers and API routes build AdGuard clients through app.state so tests can inject a mock transport.
    notifier = Notifier(session_factory, {p.name: p for p in (EmailProvider(), WebhookProvider())}, box)
    scanner = Scanner(
        session_factory,
        [ArpScanProvider(), NeighborProvider(), AdGuardProvider(lambda cfg: app.state.adguard_client_factory(cfg)),
         MdnsProvider(), SsdpProvider()],
        box,
        notify=notifier.dispatch,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        run_migrations(config.db_url, db_key)
        with session_factory() as db:
            rules.encrypt_legacy_fields(db, box, notifier.providers)  # e.g. webhook URLs saved before they were encrypted
        if config.scheduler_enabled:
            scanner.start()
        yield
        scanner.stop()
        engine.dispose()

    app = FastAPI(
        title="LanWarden",
        version=__version__,
        # Interactive docs are served below, behind login: no reason to show an API map to strangers.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.config = config
    app.state.session_factory = session_factory
    app.state.scanner = scanner
    app.state.box = box
    app.state.secret_key = secret_key
    app.state.mfa_signer = URLSafeTimedSerializer(secret_key, salt="lanwarden-mfa-login")
    app.state.notifier = notifier
    app.state.adguard_client_factory = AdGuardClient
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        session_cookie="ga_session",
        max_age=config.session_hours * 3600,
        same_site="strict",
        https_only=config.cookies_secure,
    )
    for module in (auth, system, devices, events, scanner_api, integrations, notifications, dashboard):
        app.include_router(module.router)

    @app.get("/api/openapi.json", include_in_schema=False, dependencies=[Depends(require_user)])
    def openapi_schema():
        return app.openapi()

    @app.get("/api/docs", include_in_schema=False, dependencies=[Depends(require_user)])
    def api_docs():
        return get_swagger_ui_html(openapi_url="/api/openapi.json", title="LanWarden API")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"  # device inventories and settings must not linger in caches
        if request.url.path != "/api/docs":  # Swagger UI needs a CDN script and inline code
            h["Content-Security-Policy"] = CSP
        if config.cookies_secure:  # only meaningful (and only safe) when served over HTTPS
            h["Strict-Transport-Security"] = "max-age=31536000"
        return response

    _mount_frontend(app, config.frontend_dir)
    return app


def _mount_frontend(app: FastAPI, dist: Path) -> None:
    index = dist / "index.html"
    if not index.is_file():  # API-only (development: Vite serves the UI)
        return
    root = dist.resolve()
    app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        candidate = (root / path).resolve()
        if path and candidate.is_file() and root in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(index)
