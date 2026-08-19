from __future__ import annotations

import asyncio
import json
import logging
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_phantom.models import CertificateObservation, DataOrigin, DomainInfrastructure

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data" / "mock"
CT_FIXTURES = json.loads((DATA_DIR / "ct_observations.json").read_text())
INFRA_FIXTURES = json.loads((DATA_DIR / "infrastructure_profiles.json").read_text())


class _RateLimiter:
    """Staggers the *start* of calls to a free/public API that rate-limits
    bursts (crt.sh, rdap.org), without serializing the calls themselves.

    Each caller reserves the next free slot under a lock (held only long
    enough to bump a counter, not for the HTTP round trip) then sleeps until
    that slot arrives. Calls still run concurrently after their staggered
    start - only their dispatch times are spread out - so N callers cost
    roughly N * min_interval in the worst case, not N * (min_interval +
    call duration).

    Held as a class attribute on the provider (not an instance attribute),
    so it throttles a single external host across every concurrent domain
    variant *and* every concurrent analysis request in this process -
    matching the fact that the rate limit is enforced by the remote host,
    not per-request.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = asyncio.get_running_loop().time()
            start = max(now, self._next_slot)
            self._next_slot = start + self._min_interval
        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)


class CTLogProvider(Protocol):
    async def fetch(self, domain: str) -> list[CertificateObservation]: ...


class EnrichmentProvider(Protocol):
    async def enrich(self, domain: str) -> DomainInfrastructure: ...


def _select_profile(domain: str, fixtures: dict[str, object]) -> object:
    for key, value in fixtures.items():
        if key != "fallback" and key in domain:
            return value
    return fixtures["fallback"]


def mock_certificate_observations(domain: str) -> list[CertificateObservation]:
    now = datetime.now(UTC)
    profile = _select_profile(domain, CT_FIXTURES)
    observations: list[CertificateObservation] = []
    for item in profile:
        identities = [
            entry.format(domain=domain) for entry in item.get("matching_identities", [domain])
        ]
        observations.append(
            CertificateObservation(
                logged_at=now - timedelta(days=item.get("days_ago", 2)),
                issuer_name=item.get("issuer_name", "Mock CA"),
                common_name=domain,
                matching_identities=identities,
                source="offline-fixture",
                origin=DataOrigin.MOCK,
            )
        )
    return observations


def mock_infrastructure(domain: str) -> DomainInfrastructure:
    profile = _select_profile(domain, INFRA_FIXTURES)
    return DomainInfrastructure(
        ip_addresses=profile.get("ip_addresses", []),
        name_servers=profile.get("name_servers", []),
        rdap_org=profile.get("rdap_org"),
        registrar=profile.get("registrar"),
        asn=profile.get("asn"),
        asn_org=profile.get("asn_org"),
        hosted_country=profile.get("hosted_country"),
        reputation_tags=profile.get("reputation_tags", []),
        source="offline-fixture",
        origin=DataOrigin.MOCK,
    )


class CrtShProvider:
    # crt.sh has no published rate limit but throws 429s well under one
    # request/second when a batch of lookups lands at once (observed while
    # analyzing 10 domain variants concurrently).
    _rate_limiter = _RateLimiter(min_interval=1.2)

    def __init__(self, settings: Settings, offline_mode: bool) -> None:
        self.settings = settings
        self.offline_mode = offline_mode
        self.http = HttpProvider(settings)

    async def fetch(self, domain: str) -> list[CertificateObservation]:
        if self.offline_mode:
            return mock_certificate_observations(domain)

        try:
            await self._rate_limiter.wait()
            raw = await self.http.get_json(
                self.settings.crtsh_base_url, params={"q": domain, "output": "json"}
            )
        except Exception as exc:
            logger.warning("ct_lookup_failed", extra={"domain": domain, "error": str(exc)})
            return mock_certificate_observations(domain)

        observations: list[CertificateObservation] = []
        if not isinstance(raw, list):
            return observations

        for item in raw[:5]:
            entry_ts = item.get("entry_timestamp")
            try:
                logged_at = (
                    datetime.fromisoformat(entry_ts.replace(" ", "T")).astimezone(UTC)
                    if entry_ts
                    else datetime.now(UTC)
                )
            except ValueError:
                logged_at = datetime.now(UTC)
            observations.append(
                CertificateObservation(
                    logged_at=logged_at,
                    issuer_name=item.get("issuer_name", "unknown"),
                    common_name=item.get("common_name", domain),
                    matching_identities=str(item.get("name_value", domain)).split("\n"),
                    source="crt.sh",
                    origin=DataOrigin.LIVE,
                )
            )
        return observations


class CompositeEnrichmentProvider:
    # rdap.org fronts multiple registries and 429s quickly under concurrent
    # lookups (observed while enriching 10 domain variants at once).
    _rate_limiter = _RateLimiter(min_interval=1.0)

    def __init__(self, settings: Settings, offline_mode: bool) -> None:
        self.settings = settings
        self.offline_mode = offline_mode
        self.http = HttpProvider(settings)

    async def enrich(self, domain: str) -> DomainInfrastructure:
        if self.offline_mode:
            return mock_infrastructure(domain)

        infrastructure = DomainInfrastructure(source="live-composite", origin=DataOrigin.LIVE)
        infrastructure.ip_addresses = self._resolve_ips(domain)
        infrastructure.name_servers = []

        try:
            await self._rate_limiter.wait()
            rdap_data = await self.http.best_effort(
                lambda: self.http.get_json(f"{self.settings.rdap_base_url}{domain}")
            )
            if isinstance(rdap_data, dict):
                infrastructure.registrar = _extract_registrar(rdap_data)
                infrastructure.rdap_org = _extract_org(rdap_data)
                infrastructure.name_servers = [
                    item.get("ldhName", "")
                    for item in rdap_data.get("nameservers", [])
                    if item.get("ldhName")
                ]
        except Exception as exc:
            logger.warning("rdap_lookup_failed", extra={"domain": domain, "error": str(exc)})

        if infrastructure.ip_addresses:
            await self._rate_limiter.wait()
            ip_context = await self.http.best_effort(
                lambda: self.http.get_json(
                    f"{self.settings.rdap_ip_base_url}{infrastructure.ip_addresses[0]}"
                )
            )
            if isinstance(ip_context, dict):
                start_autnum = ip_context.get("startAutnum")
                end_autnum = ip_context.get("endAutnum")
                infrastructure.asn = (
                    f"AS{start_autnum}"
                    if isinstance(start_autnum, int)
                    else f"AS{end_autnum}"
                    if isinstance(end_autnum, int)
                    else None
                )
                infrastructure.asn_org = _extract_org(ip_context) or ip_context.get("name")
                country = ip_context.get("country")
                infrastructure.hosted_country = country if isinstance(country, str) else None
            if domain.startswith("login-") or domain.endswith("secure.com") or "verify" in domain:
                infrastructure.reputation_tags.append("recent-hosting-pattern")

        return infrastructure

    @staticmethod
    def _resolve_ips(domain: str) -> list[str]:
        try:
            results = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        ips = []
        for item in results:
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips


def _extract_registrar(rdap_data: dict) -> str | None:
    for entity in rdap_data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            return _flatten_vcard(entity.get("vcardArray", []))
    return None


def _extract_org(rdap_data: dict) -> str | None:
    for entity in rdap_data.get("entities", []):
        org = _flatten_vcard(entity.get("vcardArray", []))
        if org:
            return org
    return None


def _flatten_vcard(vcard_array: list) -> str | None:
    if len(vcard_array) < 2:
        return None
    for row in vcard_array[1]:
        if row[0] in {"fn", "org"} and len(row) >= 4:
            return row[3]
    return None
