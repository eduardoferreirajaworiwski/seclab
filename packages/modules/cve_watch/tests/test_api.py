from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab_cve_watch.routes import router


def build_client(db_session):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/cve_watch")
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def test_create_and_fetch_digest_via_api(db_session):
    client = build_client(db_session)

    create_response = client.post("/api/v1/cve_watch/digests", json={"offline_mode": True})
    assert create_response.status_code == 200
    payload = create_response.json()
    assert payload["cves"]
    assert payload["summary"]["headline"]

    fetch_response = client.get(f"/api/v1/cve_watch/digests/{payload['digest_id']}")
    assert fetch_response.status_code == 200
    assert fetch_response.json()["digest_id"] == payload["digest_id"]


def test_list_recent_digests_via_api(db_session):
    client = build_client(db_session)
    client.post("/api/v1/cve_watch/digests", json={"offline_mode": True})

    list_response = client.get("/api/v1/cve_watch/digests?limit=5")
    assert list_response.status_code == 200
    assert len(list_response.json()["digests"]) == 1


def test_get_missing_digest_returns_404(db_session):
    client = build_client(db_session)
    response = client.get("/api/v1/cve_watch/digests/does-not-exist")
    assert response.status_code == 404
