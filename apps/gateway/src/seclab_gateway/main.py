import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from seclab.core.config import get_settings
from seclab.core.db import init_db
from seclab.core.logging import configure_logging
from seclab.core.rate_limit import get_limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from seclab_gateway.registry import load_manifests, mount_routers, register_models

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("seclab.gateway")

manifests = load_manifests()


@asynccontextmanager
async def lifespan(app: FastAPI):
    register_models(manifests)
    init_db()
    logger.info("gateway_started", extra={"modules": [m.name for m in manifests]})
    yield
    logger.info("gateway_stopped")


app = FastAPI(
    title="SecLab Gateway",
    description="Unified API for the seclab personal security laboratory.",
    version="0.1.0",
    lifespan=lifespan,
    # /docs and /openapi.json expose the full route/schema surface without
    # needing an API key (auth only gates the routes themselves, not the
    # schema describing them) - disabled here to match the posture
    # sensor_chimera's app already ships with.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

limiter = get_limiter(default_limits=[settings.rate_limit_default])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# SlowAPIMiddleware is what actually applies default_limits to every route -
# without it, Limiter(default_limits=...) is inert and only routes carrying
# an explicit @limiter.limit(...) decorator would ever be throttled (none
# of this gateway's routes do).
app.add_middleware(SlowAPIMiddleware)

# No allow_origins=["*"] on an authenticated API - driven by config instead
# (fixes the CORS posture both original scopepilot and chimera shipped with).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    logger.warning(
        "request_validation_failed",
        extra={"path": str(request.url.path), "errors": exc.errors()},
    )
    return JSONResponse(
        status_code=422,
        content={"detail": "request validation failed", "error_code": "validation_error"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled_api_exception", extra={"path": str(request.url.path)})
    return JSONResponse(
        status_code=500,
        content={"detail": "internal server error", "error_code": "internal_error"},
    )


@app.get("/api/v1/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": app.version,
        "environment": settings.env,
        "offline_mode": settings.offline_mode,
        "modules": [m.name for m in manifests],
    }


mount_routers(app, manifests)
