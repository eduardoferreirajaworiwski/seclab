import pytest
import seclab_sensor_chimera.app as chimera_app
from seclab.core.events import Event, EventBus
from starlette.testclient import TestClient


class SpySink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def emit(self, event: Event) -> None:
        self.events.append(event)


class FailingSink:
    async def emit(self, event: Event) -> None:
        raise RuntimeError("webhook is down")


async def _fake_lookup(ip: str) -> dict:
    return {"country": "Testland", "city": "Testville", "isp": "Test ISP"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(chimera_app.geoip, "lookup", _fake_lookup)
    monkeypatch.setattr(
        chimera_app,
        "chimera_settings",
        chimera_app.chimera_settings.model_copy(
            update={"tarpit_min_seconds": 0, "tarpit_max_seconds": 0}
        ),
    )
    return TestClient(chimera_app.app)


def test_serves_aws_decoy_for_sensitive_path(client, monkeypatch):
    spy = SpySink()
    monkeypatch.setattr(chimera_app, "event_bus", EventBus([spy]))

    response = client.get("/.aws/credentials")
    assert response.status_code == 200
    payload = response.json()
    assert payload["Type"] == "AWS-HMAC"
    assert len(spy.events) == 1
    assert spy.events[0].payload["suspicious"] is True


def test_serves_dotenv_decoy(client, monkeypatch):
    spy = SpySink()
    monkeypatch.setattr(chimera_app, "event_bus", EventBus([spy]))

    response = client.get("/.env")
    assert response.status_code == 200
    assert "DB_HOST" in response.text


def test_default_path_returns_generic_success(client, monkeypatch):
    spy = SpySink()
    monkeypatch.setattr(chimera_app, "event_bus", EventBus([spy]))

    response = client.get("/some/random/path")
    assert response.status_code == 200
    assert response.json() == {"status": "success", "data": None}
    assert spy.events[0].payload["suspicious"] is False


def test_failing_event_sink_does_not_crash_the_request(client, monkeypatch):
    monkeypatch.setattr(chimera_app, "event_bus", EventBus([FailingSink()]))

    response = client.get("/index.html")
    assert response.status_code == 200
