import asyncio

from seclab.core.config import Settings
from seclab_osint_breach.models import BreachCheckRequest, WatchedIdentifier
from seclab_osint_breach.service import BreachCheckService


def test_run_check_returns_exposures_for_known_identifiers(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = BreachCheckService(settings, db_session)
    request = BreachCheckRequest(
        offline_mode=True,
        identifiers=[
            WatchedIdentifier(identifier="alice@example.test", identifier_type="email"),
            WatchedIdentifier(identifier="acme-corp.test", identifier_type="domain"),
        ],
    )

    result = asyncio.run(service.run_check(request))

    assert result.exposures
    assert any(e.identifier == "alice@example.test" for e in result.exposures)
    assert any(e.identifier == "acme-corp.test" for e in result.exposures)
    assert result.summary.headline
    assert result.report_markdown.startswith("# OSINT Breach Check")


def test_run_check_with_no_exposures(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = BreachCheckService(settings, db_session)
    request = BreachCheckRequest(
        offline_mode=True,
        identifiers=[
            WatchedIdentifier(identifier="nobody@nowhere.test", identifier_type="email"),
        ],
    )

    result = asyncio.run(service.run_check(request))

    assert result.exposures == []
    assert result.summary.headline


def test_check_can_be_retrieved_and_listed(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = BreachCheckService(settings, db_session)
    request = BreachCheckRequest(
        offline_mode=True,
        identifiers=[WatchedIdentifier(identifier="bob@example.test", identifier_type="email")],
    )
    result = asyncio.run(service.run_check(request))

    fetched = service.get_check(result.check_id)
    assert fetched is not None
    assert fetched.check_id == result.check_id

    recent = service.list_recent_checks(limit=5)
    assert any(item.check_id == result.check_id for item in recent)
