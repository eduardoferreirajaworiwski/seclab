import asyncio

from seclab.security.scope_guard import ProgramPolicy
from seclab_attack_surface.models import AssetTarget, SurfaceScanRequest
from seclab_attack_surface.service import AttackSurfaceService


class _RaisingCtProvider:
    """A CT provider that fails the test if it is ever called - proves the
    out-of-scope short-circuit happens before any discovery call."""

    async def fetch(self, domain: str):
        raise AssertionError(f"CrtShProvider.fetch() must not be called for {domain!r}")


class _RaisingConnector:
    async def __call__(self, host: str, port: int, timeout: float) -> bool:
        raise AssertionError(f"port connector must not be called for {host}:{port}")


async def _raising_resolver(hostname: str) -> list[str]:
    raise AssertionError(f"DNS resolver must not be called for {hostname!r}")


class _FakeSubdomain:
    def __init__(self, name: str) -> None:
        self.matching_identities = [name]


class _FakeCtProvider:
    def __init__(self, subdomains: list[str]) -> None:
        self._subdomains = subdomains
        self.calls: list[str] = []

    async def fetch(self, domain: str):
        self.calls.append(domain)
        return [_FakeSubdomain(name) for name in self._subdomains]


def _make_resolver(mapping: dict[str, list[str]]):
    async def resolver(hostname: str) -> list[str]:
        return mapping.get(hostname, [])

    return resolver


def _make_connector(open_ports_by_host: dict[str, set[int]]):
    async def connector(host: str, port: int, timeout: float) -> bool:
        return port in open_ports_by_host.get(host, set())

    return connector


def _in_scope_policy() -> ProgramPolicy:
    return ProgramPolicy(allowed_domains=["example.com", "*.example.com"])


def test_out_of_scope_domain_never_triggers_discovery_or_probing():
    request = SurfaceScanRequest(
        target=AssetTarget(domain="not-allowed.example.org"),
        scope_policy=_in_scope_policy(),
    )
    service = AttackSurfaceService(
        ct_provider=_RaisingCtProvider(),
        resolver=_raising_resolver,
        connector=_RaisingConnector(),
    )

    result = asyncio.run(service.run_scan(request))

    assert result.in_scope is False
    assert result.hosts == []
    markdown_lower = result.report_markdown.lower()
    assert "scope" in markdown_lower


def test_in_scope_scan_returns_discovered_hosts_with_tags(db_session):
    ct_provider = _FakeCtProvider(["app.example.com", "example.com"])
    resolver = _make_resolver(
        {
            "app.example.com": ["10.0.0.1"],
            "example.com": ["10.0.0.2"],
        }
    )
    connector = _make_connector(
        {
            "app.example.com": {80, 443, 3389},
            "example.com": {80, 443},
        }
    )
    service = AttackSurfaceService(
        ct_provider=ct_provider, resolver=resolver, connector=connector, db=db_session
    )
    request = SurfaceScanRequest(
        target=AssetTarget(domain="example.com"), scope_policy=_in_scope_policy()
    )

    result = asyncio.run(service.run_scan(request))

    assert result.in_scope is True
    assert ct_provider.calls == ["example.com"]
    hostnames = {host.hostname for host in result.hosts}
    assert hostnames == {"app.example.com", "example.com"}

    app_host = next(h for h in result.hosts if h.hostname == "app.example.com")
    assert app_host.ip_addresses == ["10.0.0.1"]
    assert sorted(app_host.open_ports) == [80, 443, 3389]
    assert app_host.unexpected_exposure_tags == ["rdp-exposed"]

    plain_host = next(h for h in result.hosts if h.hostname == "example.com")
    assert plain_host.unexpected_exposure_tags == []

    assert result.report_markdown.startswith("# Attack Surface Scan")
    assert result.metadata["host_count"] == 2


def test_scan_result_can_be_persisted_and_retrieved(db_session):
    ct_provider = _FakeCtProvider(["example.com"])
    resolver = _make_resolver({"example.com": ["10.0.0.2"]})
    connector = _make_connector({"example.com": set()})
    service = AttackSurfaceService(
        ct_provider=ct_provider, resolver=resolver, connector=connector, db=db_session
    )
    request = SurfaceScanRequest(
        target=AssetTarget(domain="example.com"), scope_policy=_in_scope_policy()
    )

    result = asyncio.run(service.run_scan(request))
    fetched = service.get_scan(result.scan_id)

    assert fetched is not None
    assert fetched.scan_id == result.scan_id

    recent = service.list_recent_scans(limit=5)
    assert any(item.scan_id == result.scan_id for item in recent)


def test_out_of_scope_scan_is_still_persisted_for_audit_visibility(db_session):
    # Mirrors recon's TargetService: an out-of-scope attempt is recorded
    # (in_scope=False) for audit visibility, even though no discovery or
    # probing work happened for it.
    request = SurfaceScanRequest(
        target=AssetTarget(domain="not-allowed.example.org"),
        scope_policy=_in_scope_policy(),
    )
    service = AttackSurfaceService(
        ct_provider=_RaisingCtProvider(),
        resolver=_raising_resolver,
        connector=_RaisingConnector(),
        db=db_session,
    )

    result = asyncio.run(service.run_scan(request))
    fetched = service.get_scan(result.scan_id)

    assert fetched is not None
    assert fetched.in_scope is False
    assert fetched.hosts == []
