from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab_osint_breach.routes import router


def build_client(db_session):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/osint_breach")
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def test_create_and_fetch_check_via_api(db_session):
    client = build_client(db_session)

    create_response = client.post(
        "/api/v1/osint_breach/checks",
        json={
            "offline_mode": True,
            "identifiers": [
                {"identifier": "alice@example.test", "identifier_type": "email"},
            ],
        },
    )
    assert create_response.status_code == 200
    payload = create_response.json()
    assert payload["exposures"]
    assert payload["summary"]["headline"]

    fetch_response = client.get(f"/api/v1/osint_breach/checks/{payload['check_id']}")
    assert fetch_response.status_code == 200
    assert fetch_response.json()["check_id"] == payload["check_id"]


def test_list_recent_checks_via_api(db_session):
    client = build_client(db_session)
    client.post(
        "/api/v1/osint_breach/checks",
        json={
            "offline_mode": True,
            "identifiers": [{"identifier": "bob@example.test", "identifier_type": "email"}],
        },
    )

    list_response = client.get("/api/v1/osint_breach/checks?limit=5")
    assert list_response.status_code == 200
    assert len(list_response.json()["checks"]) == 1


def test_get_missing_check_returns_404(db_session):
    client = build_client(db_session)
    response = client.get("/api/v1/osint_breach/checks/does-not-exist")
    assert response.status_code == 404
