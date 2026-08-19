from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

from seclab.core.config import Settings

MAX_REDIRECTS = 5


class EgressBlockedError(Exception):
    """Raised when a request targets a host forbidden by the egress policy."""


class EgressPolicy:
    """Blocks requests to private/loopback/link-local ranges and IP literals,
    and optionally restricts to an explicit host allowlist.

    Defense-in-depth for any module that fetches attacker- or user-influenced
    URLs (domain enrichment, OSINT lookups, honeypot GeoIP, etc.).
    """

    def __init__(self, allowlist: list[str] | None = None) -> None:
        self._allowlist = {host.lower() for host in (allowlist or [])}

    def check(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise EgressBlockedError(f"scheme not allowed: {parsed.scheme!r}")

        host = parsed.hostname
        if not host:
            raise EgressBlockedError("URL has no hostname")

        if self._allowlist and host.lower() not in self._allowlist:
            raise EgressBlockedError(f"host not in egress allowlist: {host!r}")

        self._check_ip_literal_or_resolution(host)

    def _check_ip_literal_or_resolution(self, host: str) -> None:
        candidates: list[str] = []
        try:
            ipaddress.ip_address(host)
            candidates = [host]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
                candidates = [info[4][0] for info in infos]
            except socket.gaierror:
                return

        for candidate in candidates:
            ip = ipaddress.ip_address(candidate)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise EgressBlockedError(f"destination resolves to a forbidden range: {ip}")


class HttpProvider:
    def __init__(self, settings: Settings, *, egress_policy: EgressPolicy | None = None) -> None:
        self._timeout = settings.http_timeout
        self._retries = settings.http_retries
        self._headers = {"User-Agent": settings.user_agent}
        self._egress = egress_policy or EgressPolicy(settings.http_egress_allowlist)

    async def get_json(self, url: str, params: dict[str, str] | None = None) -> list | dict:
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                return await self._get_json_following_redirects(url, params)
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                await asyncio.sleep(0.2 * (attempt + 1))
        if last_error:
            raise last_error
        return {}

    async def _get_json_following_redirects(
        self, url: str, params: dict[str, str] | None
    ) -> list | dict:
        # Redirects are followed manually, one hop at a time, instead of via
        # httpx's follow_redirects=True: each hop's URL is re-validated
        # against the egress policy before it's requested, so a redirect
        # can't be used to smuggle a request to a private/loopback address
        # or a host outside the allowlist (e.g. a compromised or malicious
        # response from an otherwise-trusted host like rdap.org).
        current_url = url
        current_params = params
        for _ in range(MAX_REDIRECTS + 1):
            self._egress.check(current_url)
            async with httpx.AsyncClient(
                timeout=self._timeout,
                headers=self._headers,
                follow_redirects=False,
            ) as client:
                response = await client.get(current_url, params=current_params)

            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    response.raise_for_status()
                    return {}
                current_url = urljoin(current_url, location)
                current_params = None
                continue

            response.raise_for_status()
            return response.json()

        raise httpx.TooManyRedirects(f"exceeded {MAX_REDIRECTS} redirects for {url}")

    async def post_json(
        self,
        url: str,
        json_body: dict[str, object],
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        self._egress.check(url)
        request_headers = dict(self._headers)
        if headers:
            request_headers.update(headers)

        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    headers=request_headers,
                    follow_redirects=False,
                ) as client:
                    response = await client.post(url, json=json_body)
                    response.raise_for_status()
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise ValueError("expected dict response")
                    return payload
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                await asyncio.sleep(0.2 * (attempt + 1))
        if last_error:
            raise last_error
        return {}

    async def best_effort(self, func: Callable[[], Awaitable[dict | list]]) -> dict | list:
        try:
            return await func()
        except Exception:
            return {}
