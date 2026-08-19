from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

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

    def check(self, url: str) -> str:
        """Validates `url` against policy and returns one resolved,
        validated IP address for the caller to connect to directly.

        Returning the IP - instead of leaving the HTTP client to resolve the
        hostname again itself at connect time - closes a DNS-rebinding
        TOCTOU window: a short-TTL record can legitimately answer publicly
        here and point at a private/loopback address a moment later, at the
        actual connection.
        """
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise EgressBlockedError(f"scheme not allowed: {parsed.scheme!r}")

        host = parsed.hostname
        if not host:
            raise EgressBlockedError("URL has no hostname")

        if self._allowlist and host.lower() not in self._allowlist:
            raise EgressBlockedError(f"host not in egress allowlist: {host!r}")

        return self._resolve_and_validate(host)

    def _resolve_and_validate(self, host: str) -> str:
        try:
            ipaddress.ip_address(host)
            candidates = [host]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror as exc:
                # A resolution failure means the destination can't be proven
                # safe - fail closed. This used to `return` (allow the
                # request through) on the theory that a name that doesn't
                # resolve can't be dangerous, but that's exactly backwards:
                # it's the one case where nothing has actually been checked.
                raise EgressBlockedError(f"could not resolve host: {host!r}") from exc
            candidates = [info[4][0] for info in infos]

        for candidate in candidates:
            ip = ipaddress.ip_address(candidate)
            # `is_global` alone still admits multicast (e.g. 224.0.0.1 has
            # is_global=True), so it's checked explicitly. Using
            # "not is_global" instead of enumerating forbidden ranges is
            # deliberately fail-closed by construction: it also catches
            # ranges an explicit list can miss - e.g. 100.64.0.0/10 (CGNAT),
            # which is neither is_private nor is_loopback but still isn't
            # publicly routable.
            if ip.is_multicast or not ip.is_global:
                raise EgressBlockedError(f"destination resolves to a forbidden range: {ip}")
            return candidate  # first validated candidate is the one used

        raise EgressBlockedError(f"host did not resolve to any address: {host!r}")


def _pin_host(url: str, ip: str) -> str:
    """Rewrites `url`'s host to `ip`, keeping scheme/port/path/query/auth
    intact, so the HTTP client connects to exactly the address that was
    validated instead of resolving the hostname again itself."""
    parsed = urlsplit(url)
    netloc = f"[{ip}]" if ":" in ip else ip
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        userinfo = (
            parsed.username
            if parsed.password is None
            else f"{parsed.username}:{parsed.password}"
        )
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit(parsed._replace(netloc=netloc))


class HttpProvider:
    def __init__(
        self,
        settings: Settings,
        *,
        egress_policy: EgressPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._timeout = settings.http_timeout
        self._retries = settings.http_retries
        self._headers = {"User-Agent": settings.user_agent}
        self._egress = egress_policy or EgressPolicy(settings.http_egress_allowlist)
        self._transport = transport

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
            response = await self._send_validated("GET", current_url, params=current_params)

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
        request_headers = dict(self._headers)
        if headers:
            request_headers.update(headers)

        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                response = await self._send_validated(
                    "POST", url, json_body=json_body, headers=request_headers
                )
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

    async def _send_validated(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        ip = self._egress.check(url)
        original_host = urlsplit(url).hostname
        pinned_url = _pin_host(url, ip)

        request_headers = dict(headers or self._headers)
        request_headers["Host"] = original_host

        async with httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=False, transport=self._transport
        ) as client:
            request = client.build_request(
                method,
                pinned_url,
                params=params,
                json=json_body,
                headers=request_headers,
                # Pins TLS's SNI (and, in turn, certificate hostname
                # verification) to the original hostname even though the
                # connection itself goes to the validated IP literal above -
                # otherwise HTTPS to a name-based/CDN-fronted host like
                # crt.sh would either fail verification or route wrong.
                extensions={"sni_hostname": original_host},
            )
            return await client.send(request)

    async def best_effort(self, func: Callable[[], Awaitable[dict | list]]) -> dict | list:
        try:
            return await func()
        except Exception:
            return {}
