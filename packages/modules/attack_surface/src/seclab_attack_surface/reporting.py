from seclab.reporting.exporters import MarkdownReportBuilder

from seclab_attack_surface.models import SurfaceScanResult


def build_markdown_report(result: SurfaceScanResult) -> str:
    builder = (
        MarkdownReportBuilder("Attack Surface Scan")
        .meta(
            scan_id=result.scan_id,
            created_at=result.created_at.isoformat(),
            domain=result.target.domain,
            in_scope=result.in_scope,
            hosts_discovered=len(result.hosts),
        )
    )

    if not result.in_scope:
        builder.section("Scope Gate: Blocked").paragraph(
            f"'{result.target.domain}' is not covered by the submitted scope policy's "
            "allowlist. No subdomain discovery, DNS resolution, or port probing was "
            "performed - this scan made zero outbound network calls."
        )
        return builder.build()

    builder.section("Discovered Hosts")
    if not result.hosts:
        builder.paragraph("No hosts discovered for this domain.")
    for host in result.hosts:
        builder.section(host.hostname, level=3)
        builder.bullets(
            [
                f"IP addresses: {', '.join(host.ip_addresses) or 'none resolved'}",
                f"Open ports: {', '.join(str(p) for p in host.open_ports) or 'none open'}",
                f"Exposure tags: {', '.join(host.unexpected_exposure_tags) or 'none'}",
            ]
        )

    all_tags = sorted({tag for host in result.hosts for tag in host.unexpected_exposure_tags})
    builder.section("Exposure Summary")
    builder.bullets(all_tags or ["No unexpected exposures detected."])

    return builder.build()
