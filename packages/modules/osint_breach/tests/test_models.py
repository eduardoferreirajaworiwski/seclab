from seclab_osint_breach.models import BreachExposure, DataOrigin, WatchedIdentifier


def test_watched_identifier_roundtrip():
    identifier = WatchedIdentifier(identifier="alice@example.test", identifier_type="email")
    assert identifier.identifier_type == "email"


def test_breach_exposure_defaults_to_mock_origin():
    exposure = BreachExposure(
        identifier="alice@example.test",
        breach_name="ExampleBreach",
        breach_date="2020-01-01T00:00:00Z",
        data_classes=["passwords"],
        source="HIBP",
    )
    assert exposure.origin == DataOrigin.MOCK
