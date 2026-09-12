from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab_attack_surface.routes import get_attack_surface_service, router


def build_client(db_session, *, fake_service=None):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/attack_surface")
    app.dependency_overrides[get_db] = lambda: db_session
    if fake_service is not None:
        app.dependency_overrides[get_attack_surface_service] = lambda: fake_service
    return TestClient(app)


IN_SCOPE_BODY = {
    "target": {"domain": "example.com"},
    "scope_policy": {"allowed_domains": ["example.com", "*.example.com"]},
}

OUT_OF_SCOPE_BODY = {
    "target": {"domain": "not-allowed.example.org"},
    "scope_policy": {"allowed_domains": ["example.com"]},
}


def test_create_scan_blocked_when_out_of_scope_makes_no_network_calls(db_session):
    client = build_client(db_session)

    response = client.post("/api/v1/attack_surface/scans", json=OUT_OF_SCOPE_BODY)

    assert response.status_code == 200
    payload = response.json()
    assert payload["in_scope"] is False
    assert payload["hosts"] == []


def test_list_and_get_scan_via_api(db_session):
    client = build_client(db_session)

    create_response = client.post("/api/v1/attack_surface/scans", json=OUT_OF_SCOPE_BODY)
    scan_id = create_response.json()["scan_id"]

    list_response = client.get("/api/v1/attack_surface/scans")
    assert list_response.status_code == 200
    assert any(item["scan_id"] == scan_id for item in list_response.json()["scans"])

    get_response = client.get(f"/api/v1/attack_surface/scans/{scan_id}")
    assert get_response.status_code == 200
    assert get_response.json()["scan_id"] == scan_id


def test_get_missing_scan_returns_404(db_session):
    client = build_client(db_session)

    response = client.get("/api/v1/attack_surface/scans/does-not-exist")

    assert response.status_code == 404
