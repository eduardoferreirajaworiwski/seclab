from fastapi.testclient import TestClient
from seclab_gateway.main import app


def test_health_lists_every_mounted_module():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert set(payload["modules"]) == {"phantom", "recon", "monitor"}


def test_sensor_chimera_is_never_mounted_on_the_gateway():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert "sensor_chimera" not in response.json()["modules"]


def test_phantom_offline_analysis_via_gateway():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/phantom/analyses",
            json={
                "target": "acme",
                "target_type": "brand",
                "offline_mode": True,
                "max_variants": 5,
            },
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
