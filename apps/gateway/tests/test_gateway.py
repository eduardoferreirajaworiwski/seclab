from fastapi.testclient import TestClient
from seclab.core.config import Settings
from seclab.core.db import SessionLocal
from seclab.security.keys import hash_api_key
from seclab.security.models import Role, User
from seclab_gateway.main import app, settings


def _create_user(*, username: str, role: str = Role.ANALYST.value) -> str:
    """Mints a user directly against the gateway's DB session and returns
    the raw API key, mirroring what `seclab users create` does out-of-band."""
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    raw_key = f"key-{username}"
    with SessionLocal() as db:
        db.add(User(username=username, role=role, api_key_hash=hash_api_key(raw_key, settings)))
        db.commit()
    return raw_key


def test_health_lists_every_mounted_module():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert set(payload["modules"]) == {"phantom", "recon", "monitor", "threatlens", "cve_watch"}


def test_health_does_not_require_authentication():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200


def test_sensor_chimera_is_never_mounted_on_the_gateway():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert "sensor_chimera" not in response.json()["modules"]


def test_phantom_analysis_requires_authentication():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/phantom/analyses",
            json={"target": "acme", "target_type": "brand", "max_variants": 5},
        )
        assert response.status_code == 401


def test_monitor_matches_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/api/v1/monitor/matches")
        assert response.status_code == 401


def test_phantom_offline_analysis_via_gateway():
    with TestClient(app) as client:
        api_key = _create_user(username="phantom-tester")
        response = client.post(
            "/api/v1/phantom/analyses",
            json={
                "target": "acme",
                "target_type": "brand",
                "offline_mode": True,
                "max_variants": 5,
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert response.status_code == 200
        assert response.json()["assets"]


def test_recon_requires_authentication_via_gateway():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/recon/programs",
            json={"name": "Acme", "description": "", "scope_policy": {}},
        )
        assert response.status_code == 401


def test_rate_limit_returns_429_once_exceeded():
    # A distinct client (host, port) isolates this test's counter bucket
    # from every other test in this file that also calls /api/v1/health
    # against the same module-level `limiter` (its in-memory storage is a
    # process-wide singleton, shared by every TestClient instance).
    limit = int(settings.rate_limit_default.split("/")[0])
    with TestClient(app, client=("203.0.113.77", 12345)) as client:
        statuses = [client.get("/api/v1/health").status_code for _ in range(limit + 1)]
    assert statuses[:-1] == [200] * limit
    assert statuses[-1] == 429


def test_unknown_route_returns_404_not_a_500():
    with TestClient(app) as client:
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404


def test_docs_and_openapi_schema_are_disabled():
    # /docs and /openapi.json expose the full route/schema surface without
    # needing an API key - auth (C1) only gates the routes themselves.
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_phantom_analysis_has_a_dedicated_tighter_rate_limit():
    # phantom's default_limits bucket is shared with every other route;
    # this asserts its OWN limit trips before the global 60/minute would,
    # proving a dedicated slowapi limit is actually attached to this route.
    api_key = _create_user(username="phantom-rate-tester")
    tight_limit = 5  # must match PHANTOM_ANALYSIS_RATE_LIMIT in routes.py
    with TestClient(app, client=("203.0.113.88", 12345)) as client:
        statuses = [
            client.post(
                "/api/v1/phantom/analyses",
                json={
                    "target": "acme",
                    "target_type": "brand",
                    "offline_mode": True,
                    "max_variants": 3,
                },
                headers={"Authorization": f"Bearer {api_key}"},
            ).status_code
            for _ in range(tight_limit + 1)
        ]
    assert statuses[:-1] == [200] * tight_limit
    assert statuses[-1] == 429
