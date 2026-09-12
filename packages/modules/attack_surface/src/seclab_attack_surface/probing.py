from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

# Small, fixed port list - not a full nmap-style sweep - to keep this
# module in "safe, low-noise, personal-lab" territory per the plan.
COMMON_PORTS: list[int] = [80, 443, 22, 21, 3389]

PROBE_TIMEOUT_SECONDS = 1.5
DEFAULT_CONCURRENCY = 10

Connector = Callable[[str, int, float], Awaitable[bool]]
Resolver = Callable[[str], Awaitable[list[str]]]


async def default_connector(host: str, port: int, timeout: float) -> bool:
    """Pure TCP-connect reachability check: open the connection, close it
    immediately, never send/receive any protocol data. Always wrapped in
    asyncio.wait_for with a short timeout so a filtered port can never hang
    the whole scan - a bare socket.connect() with no timeout is never used."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def default_resolver(hostname: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        results = await loop.getaddrinfo(hostname, None)
    except OSError:
        return []
    ips: list[str] = []
    for item in results:
        ip = item[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


async def resolve_hostname(hostname: str, *, resolver: Resolver = default_resolver) -> list[str]:
    """DNS resolution wrapped behind an injectable resolver so tests never
    need real DNS - any lookup failure resolves to an empty IP list rather
    than raising, matching every other module's best-effort enrichment
    style."""
    try:
        return await resolver(hostname)
    except OSError as exc:
        logger.warning("dns_resolution_failed", extra={"hostname": hostname, "error": str(exc)})
        return []


async def probe_ports(
    host: str,
    *,
    ports: list[int] | None = None,
    connector: Connector = default_connector,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[int]:
    """Probes `ports` (default COMMON_PORTS) on `host` concurrently, bounded
    by a semaphore, and returns the subset found open. `connector` is
    injectable so tests never touch a real socket - production code uses
    `default_connector` (asyncio.open_connection + asyncio.wait_for)."""
    target_ports = COMMON_PORTS if ports is None else ports
    semaphore = asyncio.Semaphore(concurrency)

    async def _check(port: int) -> int | None:
        async with semaphore:
            is_open = await connector(host, port, timeout)
        return port if is_open else None

    results = await asyncio.gather(*(_check(port) for port in target_ports))
    return [port for port in results if port is not None]
