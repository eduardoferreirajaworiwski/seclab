from seclab_phantom.models import CertificateObservation, DomainInfrastructure, DomainVariation
from seclab_phantom.scoring import score_asset


def test_scoring_prioritizes_suspicious_assets() -> None:
    variation = DomainVariation(
        domain="login-acme.com",
        technique="brand-prefix",
        source_target="acme",
        risk_context_tags=["credential-lure"],
    )
    certificates = [
        CertificateObservation(
            logged_at="2026-01-01T00:00:00Z",
            issuer_name="Let's Encrypt",
            common_name="login-acme.com",
            matching_identities=["login-acme.com"],
        )
    ]
    infrastructure = DomainInfrastructure(
        ip_addresses=["198.51.100.23"],
        rdap_org="Privacy Protected LLC",
        reputation_tags=["credential-harvest-theme"],
    )
    score, priority, signals, rationale = score_asset(variation, certificates, infrastructure)
    assert score >= 65
    assert priority in {"medium", "high"}
    assert signals
    assert "certificate-observed" in rationale
