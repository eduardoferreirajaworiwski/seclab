from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_osint_breach.models import BreachExposure, DataOrigin, WatchedIdentifier

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data" / "mock"

HIBP_BREACHED_ACCOUNT_URL_TEMPLATE = "{base_url}/breachedaccount/{account}"


def _log_safe_identifier(identifier: WatchedIdentifier) -> str:
    """Returns a value safe to log at any level. Emails are potentially
    sensitive even in a personal lab, so they are hashed rather than
    logged raw; domains are not sensitive and are logged as-is. See this
    module's README for the security rationale (and a callout of the
    pre-existing, narrower inconsistency in seclab_phantom.ai_summary)."""
    if identifier.identifier_type == "email":
        digest = hashlib.sha256(identifier.identifier.encode("utf-8")).hexdigest()[:12]
        return f"email:sha256:{digest}"
    return f"domain:{identifier.identifier}"


def _parse_datetime(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def mock_exposures() -> list[BreachExposure]:
    """Loads the offline fixture set of breach exposures. Always
    available, no network call, no API key required - the offline-first
    default for this module."""
    raw = json.loads((DATA_DIR / "exposures.json").read_text())
    return [
        BreachExposure(
            identifier=item["identifier"],
            breach_name=item["breach_name"],
            breach_date=_parse_datetime(item["breach_date"]),
            data_classes=list(item.get("data_classes", [])),
            source=item.get("source", "HIBP-fixture"),
            origin=DataOrigin.MOCK,
        )
        for item in raw
    ]


def check_identifier_offline(identifier: WatchedIdentifier) -> list[BreachExposure]:
    """Filters the offline fixture set down to exposures matching a single
    watched identifier (email or domain), case-insensitively."""
    target = identifier.identifier.strip().lower()
    return [e for e in mock_exposures() if e.identifier.strip().lower() == target]


def parse_hibp_response(identifier: str, payload: list[dict[str, Any]]) -> list[BreachExposure]:
    """Parses a Have I Been Pwned `GET /breachedaccount/{account}` response
    (a JSON array of breach objects) into BreachExposure records."""
    exposures: list[BreachExposure] = []
    for item in payload:
        name = item.get("Name")
        if not name:
            continue
        exposures.append(
            BreachExposure(
                identifier=identifier,
                breach_name=str(name),
                breach_date=_parse_datetime(item.get("BreachDate")),
                data_classes=list(item.get("DataClasses", [])),
                source="HIBP",
                origin=DataOrigin.LIVE,
            )
        )
    return exposures


class BreachLookupService:
    """Checks watched identifiers against exposure data. Offline-fixture-
    first by design: the live HIBP client is only used when both
    `offline_mode` is False AND `settings.hibp_api_key` is set - exactly
    like `threatlens` gates its `gemini_api_key` AI path. HIBP only checks
    email accounts; domain identifiers are always resolved against the
    offline fixture set regardless of mode (HIBP's account-breach endpoint
    takes a single account, not a domain)."""

    def __init__(self, settings: Settings, offline_mode: bool) -> None:
        self.settings = settings
        self.offline_mode = offline_mode
        self.http = HttpProvider(settings)

    async def check(self, identifier: WatchedIdentifier) -> list[BreachExposure]:
        if (
            self.offline_mode
            or not self.settings.hibp_api_key
            or identifier.identifier_type != "email"
        ):
            return check_identifier_offline(identifier)

        url = HIBP_BREACHED_ACCOUNT_URL_TEMPLATE.format(
            base_url=self.settings.hibp_base_url, account=identifier.identifier
        )
        headers = {"hibp-api-key": self.settings.hibp_api_key.get_secret_value()}
        try:
            payload = await self.http.get_json(
                url, params={"truncateResponse": "false"}, headers=headers
            )
            if isinstance(payload, list):
                return parse_hibp_response(identifier.identifier, payload)
            return []
        except Exception as exc:
            logger.warning(
                "osint_breach_hibp_fetch_failed",
                extra={"identifier": _log_safe_identifier(identifier), "error": str(exc)},
            )
            return check_identifier_offline(identifier)

    async def check_all(
        self, identifiers: list[WatchedIdentifier]
    ) -> list[BreachExposure]:
        exposures: list[BreachExposure] = []
        for identifier in identifiers:
            exposures.extend(await self.check(identifier))
        return exposures
