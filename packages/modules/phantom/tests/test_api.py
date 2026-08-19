from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab_phantom.routes import router


def build_client(db_session):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/phantom")
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def test_create_and_fetch_analysis_via_api(db_session) -> None:
    client = build_client(db_session)

    create_response = client.post(
        "/api/v1/phantom/analyses",
        json={"target": "acme", "target_type": "brand", "offline_mode": True, "max_variants": 8},
    )
    assert create_response.status_code == 200
    payload = create_response.json()
    assert payload["assets"]
    assert payload["summary"]["headline"]

    fetch_response = client.get(f"/api/v1/phantom/analyses/{payload['analysis_id']}")
    assert fetch_response.status_code == 200
    assert fetch_response.json()["analysis_id"] == payload["analysis_id"]


def test_list_recent_analyses_via_api(db_session) -> None:
    client = build_client(db_session)

    for target in ["acme", "contoso"]:
        response = client.post(
            "/api/v1/phantom/analyses",
            json={
                "target": target,
                "target_type": "brand",
                "offline_mode": True,
                "max_variants": 8,
            },
        )
        assert response.status_code == 200

    list_response = client.get("/api/v1/phantom/analyses?limit=5")
    assert list_response.status_code == 200
    payload = list_response.json()
    assert len(payload["analyses"]) == 2
    assert payload["analyses"][0]["summary_headline"]


def test_validation_errors_reject_empty_sanitized_target(db_session) -> None:
    client = build_client(db_session)

    response = client.post(
        "/api/v1/phantom/analyses",
        json={"target": "!!!", "target_type": "brand", "offline_mode": True, "max_variants": 8},
    )
    assert response.status_code == 422
