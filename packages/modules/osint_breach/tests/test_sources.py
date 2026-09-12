from seclab_osint_breach.models import DataOrigin, WatchedIdentifier
from seclab_osint_breach.sources import (
    check_identifier_offline,
    mock_exposures,
    parse_hibp_response,
)


def test_mock_exposures_returns_offline_fixture_data():
    exposures = mock_exposures()
    assert len(exposures) >= 3
    assert all(e.origin == DataOrigin.MOCK for e in exposures)
    assert all(e.source == "HIBP-fixture" for e in exposures)


def test_check_identifier_offline_filters_by_identifier():
    identifier = WatchedIdentifier(identifier="alice@example.test", identifier_type="email")
    matches = check_identifier_offline(identifier)
    assert len(matches) == 2
    assert all(m.identifier == "alice@example.test" for m in matches)


def test_check_identifier_offline_returns_empty_for_unknown_identifier():
    identifier = WatchedIdentifier(identifier="nobody@nowhere.test", identifier_type="email")
    assert check_identifier_offline(identifier) == []


def test_check_identifier_offline_supports_domain_identifiers():
    identifier = WatchedIdentifier(identifier="acme-corp.test", identifier_type="domain")
    matches = check_identifier_offline(identifier)
    assert len(matches) == 2


SAMPLE_HIBP_RESPONSE = [
    {
        "Name": "LiveTestBreach",
        "BreachDate": "2022-05-01",
        "DataClasses": ["Email addresses", "Passwords"],
    }
]


def test_parse_hibp_response_extracts_exposures():
    exposures = parse_hibp_response("carol@example.test", SAMPLE_HIBP_RESPONSE)
    assert len(exposures) == 1
    assert exposures[0].breach_name == "LiveTestBreach"
    assert exposures[0].identifier == "carol@example.test"
    assert exposures[0].origin == DataOrigin.LIVE
    assert exposures[0].data_classes == ["Email addresses", "Passwords"]
