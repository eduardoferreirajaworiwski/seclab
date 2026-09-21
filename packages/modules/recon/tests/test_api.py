from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab.security.auth import get_current_user
from seclab_recon.routes import router


def build_client(db_session, user):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/recon")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_program_and_target_creation_via_api(db_session, make_user):
    user = make_user(username="analyst-api")
    client = build_client(db_session, user)

    create_resp = client.post(
        "/api/v1/recon/programs",
        json={
            "name": "Acme Bounty",
            "description": "",
            "scope_policy": {"allowed_domains": ["example.com"]},
        },
    )
    assert create_resp.status_code == 200
    program_id = create_resp.json()["id"]

    target_resp = client.post(
        f"/api/v1/recon/programs/{program_id}/targets",
        json={"identifier": "example.com", "target_type": "domain"},
    )
    assert target_resp.status_code == 200
    assert target_resp.json()["in_scope"] is True

    out_of_scope_resp = client.post(
        f"/api/v1/recon/programs/{program_id}/targets",
        json={"identifier": "not-example.com", "target_type": "domain"},
    )
    assert out_of_scope_resp.json()["in_scope"] is False


def test_list_hypotheses_and_executions_for_program(db_session, make_user):
    user = make_user(username="analyst-list")
    client = build_client(db_session, user)

    program_id = client.post(
        "/api/v1/recon/programs",
        json={
            "name": "List Bounty",
            "description": "",
            "scope_policy": {"allowed_domains": ["example.com"]},
        },
    ).json()["id"]
    client.post(
        f"/api/v1/recon/programs/{program_id}/targets",
        json={"identifier": "example.com", "target_type": "domain"},
    )
    hyp_resp = client.post(
        "/api/v1/recon/targets/1/hypotheses",
        json={"title": "Possible XSS", "description": "reflected input"},
    )
    assert hyp_resp.status_code == 200

    list_resp = client.get(f"/api/v1/recon/programs/{program_id}/hypotheses")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    hypothesis_id = hyp_resp.json()["id"]
    executions_resp = client.get(f"/api/v1/recon/hypotheses/{hypothesis_id}/executions")
    assert executions_resp.status_code == 200
    assert executions_resp.json() == []


def test_unauthenticated_request_is_rejected(db_session):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/recon")
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    resp = client.post(
        "/api/v1/recon/programs",
        json={"name": "Acme Bounty", "description": "", "scope_policy": {}},
    )
    assert resp.status_code == 401


def test_ai_suggest_hypotheses_returns_deterministic_fallback_when_offline(db_session, make_user):
    user = make_user(username="analyst-ai")
    client = build_client(db_session, user)

    program_id = client.post(
        "/api/v1/recon/programs",
        json={
            "name": "AI Bounty",
            "description": "",
            "scope_policy": {"allowed_domains": ["example.com"]},
        },
    ).json()["id"]
    target_id = client.post(
        f"/api/v1/recon/programs/{program_id}/targets",
        json={"identifier": "example.com", "target_type": "domain"},
    ).json()["id"]

    resp = client.post(f"/api/v1/recon/targets/{target_id}/ai-suggest-hypotheses")
    assert resp.status_code == 200
    body = resp.json()
    # Settings() defaults offline_mode=True, so no AI call is attempted -
    # the deterministic checklist fallback is what should come back here.
    assert body["model_source"] == "deterministic-fallback"
    assert len(body["suggestions"]) > 0
