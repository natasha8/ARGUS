from fastapi.testclient import TestClient

from app.main import app


def test_health_and_meta():
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    meta = client.get("/meta").json()
    assert "disclaimer" in meta
    assert any(item["id"] == "bola" for item in meta["checks"])


def test_api_rejects_scan_without_authorization():
    client = TestClient(app)
    response = client.post(
        "/scans",
        json={
            "name": "rifiutata",
            "target_base_url": "http://127.0.0.1:8001",
            "scope_confirmed": False,
            "discovery_mode": "manual",
            "manual_endpoints": [{"method": "GET", "path": "/api/account", "auth_required": True}],
            "profiles": [],
            "checks": ["bola"],
        },
    )
    assert response.status_code == 400
