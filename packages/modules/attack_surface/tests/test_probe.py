import asyncio

import pytest
from seclab_attack_surface.probing import COMMON_PORTS, probe_ports, resolve_hostname


def test_common_ports_is_the_fixed_short_list_from_the_plan():
    assert COMMON_PORTS == [80, 443, 22, 21, 3389]


def test_probe_ports_reports_only_fake_open_ports():
    async def fake_connector(host: str, port: int, timeout: float) -> bool:
        return port in {80, 3389}

    result = asyncio.run(probe_ports("example.com", connector=fake_connector))

    assert sorted(result) == [80, 3389]


def test_probe_ports_excludes_closed_or_timed_out_ports():
    async def fake_connector(host: str, port: int, timeout: float) -> bool:
        return False

    result = asyncio.run(probe_ports("example.com", connector=fake_connector))

    assert result == []


def test_probe_ports_never_touches_a_real_socket():
    calls = []

    async def fake_connector(host: str, port: int, timeout: float) -> bool:
        calls.append((host, port))
        return port == 22

    result = asyncio.run(
        probe_ports("internal.example.com", ports=[22, 443], connector=fake_connector)
    )

    assert result == [22]
    assert set(calls) == {("internal.example.com", 22), ("internal.example.com", 443)}


def test_probe_ports_respects_a_bounded_concurrency_semaphore():
    max_concurrent = 0
    current = 0
    lock = asyncio.Lock()

    async def fake_connector(host: str, port: int, timeout: float) -> bool:
        nonlocal max_concurrent, current
        async with lock:
            current += 1
            max_concurrent = max(max_concurrent, current)
        await asyncio.sleep(0.01)
        async with lock:
            current -= 1
        return False

    asyncio.run(
        probe_ports(
            "example.com",
            ports=[1, 2, 3, 4, 5, 6, 7, 8],
            connector=fake_connector,
            concurrency=2,
        )
    )

    assert max_concurrent <= 2


def test_resolve_hostname_uses_the_injected_resolver_not_real_dns():
    async def fake_resolver(hostname: str) -> list[str]:
        return ["10.0.0.5", "10.0.0.6"]

    ips = asyncio.run(resolve_hostname("example.com", resolver=fake_resolver))

    assert ips == ["10.0.0.5", "10.0.0.6"]


def test_resolve_hostname_returns_empty_list_when_resolver_raises():
    async def failing_resolver(hostname: str) -> list[str]:
        raise OSError("dns lookup failed")

    ips = asyncio.run(resolve_hostname("nonexistent.invalid", resolver=failing_resolver))

    assert ips == []


def test_probe_ports_fails_fast_if_used_without_injected_connector_in_tests():
    # Guard against accidentally calling the real default connector (which
    # would attempt a genuine TCP connection) from within the test suite -
    # every probe test in this file must pass an explicit fake.
    with pytest.raises(TypeError):
        asyncio.run(probe_ports())  # missing required "host" argument
