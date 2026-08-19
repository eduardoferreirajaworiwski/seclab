from __future__ import annotations

import asyncio
import logging
import random

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from seclab.core.config import get_settings
from seclab.core.events import Event, configure_event_bus
from seclab.core.http import HttpProvider
from seclab.core.logging import configure_logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from seclab_sensor_chimera.config import get_chimera_settings
from seclab_sensor_chimera.decoys import aws_credentials_decoy, dotenv_decoy, git_config_decoy
from seclab_sensor_chimera.detection import is_suspicious_ua, sanitize_input, touches_sensitive_path
from seclab_sensor_chimera.geoip import GeoIpLookup
from seclab_sensor_chimera.middleware import RequestSizeLimitMiddleware, SecurityHeadersMiddleware

settings = get_settings()
chimera_settings = get_chimera_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("seclab.sensor_chimera")

http = HttpProvider(settings)
geoip = GeoIpLookup(http)
event_bus = configure_event_bus(settings, http)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="SecLab Sensor: Chimera", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(SecurityHeadersMiddleware, server_label="Hidden")
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=chimera_settings.max_request_body_bytes)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=chimera_settings.allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=chimera_settings.cors_allow_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.api_route(
    "/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@limiter.limit(chimera_settings.rate_limit)
async def catch_all(request: Request, full_path: str) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    user_agent = sanitize_input(request.headers.get("user-agent", "Unknown"))
    method = request.method
    clean_path = sanitize_input(f"/{full_path}")
    path_lower = clean_path.lower()

    suspicious = is_suspicious_ua(user_agent) or touches_sensitive_path(path_lower)
    geo = await geoip.lookup(client_ip)

    logger.warning(
        "trap_triggered",
        extra={
            "ip": client_ip,
            "path": clean_path,
            "method": method,
            "suspicious": suspicious,
            "country": geo.get("country", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
        },
    )

    if suspicious or touches_sensitive_path(path_lower):
        delay = random.randint(  # noqa: S311 (tarpit delay, not a security-sensitive value)
            chimera_settings.tarpit_min_seconds, chimera_settings.tarpit_max_seconds
        )
        logger.warning("tarpit_activated", extra={"ip": client_ip, "delay_seconds": delay})
        await asyncio.sleep(delay)

    hit_label = "Suspicious" if suspicious else "Probe"
    await event_bus.publish(
        Event(
            source="sensor_chimera",
            kind="trap_triggered",
            summary=f"{hit_label} hit on {clean_path} from {client_ip}",
            severity="critical" if suspicious else "warning",
            payload={
                "ip": client_ip,
                "path": clean_path,
                "method": method,
                "user_agent": user_agent,
                "suspicious": suspicious,
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
            },
        )
    )

    if any(marker in path_lower for marker in ("aws", "iam", "credentials")):
        logger.info("serving_decoy", extra={"ip": client_ip, "decoy": "aws_credentials"})
        return Response(content=_json(aws_credentials_decoy()), media_type="application/json")

    if any(marker in path_lower for marker in ("env", "config", "secret", "settings")):
        logger.info("serving_decoy", extra={"ip": client_ip, "decoy": "dotenv"})
        return Response(content=dotenv_decoy(), media_type="text/plain")

    if ".git/config" in path_lower:
        logger.info("serving_decoy", extra={"ip": client_ip, "decoy": "git_config"})
        return Response(content=git_config_decoy(), media_type="text/plain")

    return Response(content='{"status": "success", "data": null}', media_type="application/json")


def _json(payload: dict) -> str:
    import json

    return json.dumps(payload)
