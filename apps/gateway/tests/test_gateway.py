from fastapi.testclient import TestClient
from seclab.core.config import Settings
from seclab.core.db import SessionLocal
from seclab.security.keys import hash_api_key
from seclab.security.models import Role, User
from seclab_gateway.main import app


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
        assert set(payload["modules"]) == {"phantom", "recon", "monitor"}


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


def test_unknown_route_returns_404_not_a_500():
    with TestClient(app) as client:
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
