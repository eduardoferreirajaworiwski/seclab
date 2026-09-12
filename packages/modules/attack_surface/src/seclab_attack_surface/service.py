from __future__ import annotations

import logging
from typing import Protocol

from seclab.security.scope_guard import ScopeGuardService
from sqlalchemy.orm import Session

from seclab_attack_surface.db import SurfaceScanRepository
from seclab_attack_surface.models import (
    DiscoveredHost,
    SurfaceScanListItem,
    SurfaceScanRequest,
    SurfaceScanResult,
)
from seclab_attack_surface.probing import (
    Connector,
    Resolver,
    default_connector,
    default_resolver,
    probe_ports,
    resolve_hostname,
)
from seclab_attack_surface.reporting import build_markdown_report
from seclab_attack_surface.tagging import tag_open_ports

logger = logging.getLogger(__name__)


class CTLogProvider(Protocol):
    async def fetch(self, domain: str): ...


def _extract_hostnames(domain: str, observations) -> list[str]:
    hostnames: list[str] = [domain]
    for observation in observations:
        for identity in getattr(observation, "matching_identities", []):
            cleaned = identity.strip().lower().lstrip("*.")
            if cleaned and cleaned not in hostnames:
                hostnames.append(cleaned)
    return hostnames


class AttackSurfaceService:
    """Orchestrates a scan: scope-gate FIRST, then (only if in scope)
    CT-log subdomain discovery -> DNS resolution -> port probing ->
    deterministic exposure tagging -> persistence. The scope check is the
    very first thing this method does and nothing else runs if it fails -
    this is the one module in the repo that MUST NOT skip that gate."""

    def __init__(
        self,
        *,
        ct_provider: CTLogProvider,
        resolver: Resolver = default_resolver,
        connector: Connector = default_connector,
        db: Session | None = None,
    ) -> None:
        self.ct_provider = ct_provider
        self.resolver = resolver
        self.connector = connector
        self.guard = ScopeGuardService()
        self.repository = SurfaceScanRepository(db) if db is not None else None

    async def run_scan(self, request: SurfaceScanRequest) -> SurfaceScanResult:
        scope_result = self.guard.validate_target_in_scope(
            request.scope_policy, identifier=request.target.domain, target_type="domain"
        )

        if not scope_result.in_scope:
            result = SurfaceScanResult(
                target=request.target,
                in_scope=False,
                hosts=[],
                metadata={"scope_code": scope_result.code, "scope_message": scope_result.message},
            )
            result = result.model_copy(
                update={"report_markdown": build_markdown_report(result)}
            )
            self._persist(result)
            logger.info(
                "attack_surface_scan_blocked",
                extra={"domain": request.target.domain, "code": scope_result.code},
            )
            return result

        observations = await self.ct_provider.fetch(request.target.domain)
        hostnames = _extract_hostnames(request.target.domain, observations)

        hosts: list[DiscoveredHost] = []
        for hostname in hostnames:
            ip_addresses = await resolve_hostname(hostname, resolver=self.resolver)
            open_ports = await probe_ports(hostname, connector=self.connector)
            tags = tag_open_ports(open_ports)
            hosts.append(
                DiscoveredHost(
                    hostname=hostname,
                    ip_addresses=ip_addresses,
                    open_ports=sorted(open_ports),
                    unexpected_exposure_tags=tags,
                )
            )

        draft = SurfaceScanResult(
            target=request.target,
            in_scope=True,
            hosts=hosts,
            metadata={
                "scope_code": scope_result.code,
                "host_count": len(hosts),
                "exposure_tag_count": sum(len(h.unexpected_exposure_tags) for h in hosts),
            },
        )
        result = draft.model_copy(update={"report_markdown": build_markdown_report(draft)})
        self._persist(result)
        logger.info(
            "attack_surface_scan_completed",
            extra={"domain": request.target.domain, "host_count": len(hosts)},
        )
        return result

    def _persist(self, result: SurfaceScanResult) -> None:
        if self.repository is not None:
            self.repository.save(result)

    def get_scan(self, scan_id: str) -> SurfaceScanResult | None:
        if self.repository is None:
            return None
        return self.repository.get(scan_id)

    def list_recent_scans(self, limit: int = 10) -> list[SurfaceScanListItem]:
        if self.repository is None:
            return []
        return self.repository.list_recent(limit=limit)
