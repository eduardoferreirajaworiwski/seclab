from seclab_phantom.discovery import generate_domain_variants
from seclab_phantom.models import TargetProfile


def test_generate_domain_variants_produces_expected_patterns() -> None:
    profile = TargetProfile(
        original_input="Acme",
        normalized_target="acme",
        brand_keyword="acme",
        root_domain=None,
        apex_domain=None,
    )
    results = generate_domain_variants(profile, limit=8)
    domains = {item.domain for item in results}
    assert "login-acme.com" in domains
    assert any(item.technique == "support-lure" for item in results)
    assert any(item.technique == "security-lure" for item in results)
    assert len(results) == 8
