import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.engine.runner import execute_scan
from app.models import Base, Finding
from app.schemas.scan import AuthProfileIn, ScanCreate
from app.services.scans import create_scan


def test_lab_scan_confirms_real_issues_and_skips_safe_routes(lab_servers):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    payload = ScanCreate(
        name="lab",
        target_base_url=lab_servers["lab"],
        scope_confirmed=True,
        discovery_mode="openapi",
        openapi_url=f"{lab_servers['lab']}/openapi.json",
        profiles=[
            AuthProfileIn(
                name="alice",
                role="user",
                type="bearer",
                username="alice",
                password="alice123",
                login_path="/api/login",
            ),
            AuthProfileIn(
                name="bob",
                role="user",
                type="bearer",
                username="bob",
                password="bob123",
                login_path="/api/login",
            ),
            AuthProfileIn(
                name="admin",
                role="admin",
                type="bearer",
                username="admin",
                password="admin123",
                login_path="/api/login",
            ),
        ],
        checks=[
            "bola",
            "auth_jwt",
            "data_exposure",
            "resource_limits",
            "bfla",
            "ssrf",
            "misconfig",
            "inventory",
            "unsafe_consumption",
            "injection",
        ],
        concurrency=8,
        rate_limit_rps=40,
        collaborator_base_url=lab_servers["collaborator"],
        id_probes=[101, 102, 1, 2],
    )
    scan = create_scan(db, payload)
    asyncio.run(execute_scan(db, scan.id))
    db.expire_all()
    stored = db.get(type(scan), scan.id)
    assert stored.status == "completed", stored.error_message
    findings = db.query(Finding).filter(Finding.scan_id == stored.id).all()
    assert findings, "the scan produced no findings"

    def has(category: str, **expected) -> bool:
        for finding in findings:
            if finding.category != category:
                continue
            if expected.get("status") and finding.status != expected["status"]:
                continue
            if expected.get("endpoint") and finding.endpoint_label != expected["endpoint"]:
                continue
            if expected.get("title_contains") and expected["title_contains"] not in finding.title:
                continue
            if expected.get("subtype") and (finding.evidence or {}).get("subtype") != expected["subtype"]:
                continue
            return True
        return False

    assert has("bola", status="confirmed", endpoint="GET /api/orders/{order_id}")
    assert not has("bola", endpoint="GET /api/orders/{order_id}/secure")

    jwt = [item for item in findings if item.category == "auth_jwt"]
    assert any("weak secret" in item.title for item in jwt)
    none_finding = next(item for item in jwt if "without a valid signature" in item.title)
    affected = none_finding.evidence["affected_endpoints"]
    assert any("/api/account" in item for item in affected)
    assert not any("/api/secure/me" in item for item in affected)
    assert any("expiry" in item.title.lower() for item in jwt)

    assert has("data_exposure", status="confirmed", endpoint="GET /api/profile")
    assert not has("data_exposure", endpoint="GET /api/secure/profile")
    exposure = next(item for item in findings if item.category == "data_exposure")
    assert "password_hash" in exposure.evidence["exposed_fields"]
    assert "lab-reset" not in (exposure.evidence["requests"][0]["body_excerpt"])

    jwt_titles = [item.title for item in jwt]
    assert any("role claim can be forged" in title for title in jwt_titles)

    assert has("bfla", status="confirmed", endpoint="GET /api/admin/users")
    assert not has("bfla", endpoint="GET /api/admin/audit")

    assert has("ssrf", status="confirmed", endpoint="GET /api/preview")

    assert has(
        "injection",
        status="confirmed",
        endpoint="GET /api/products/search",
        subtype="sql",
    )
    assert not has("injection", endpoint="GET /api/products/search-safe")
    assert has("injection", status="confirmed", endpoint="POST /api/items/find", subtype="nosql")
    assert has("injection", status="confirmed", endpoint="GET /api/diag/ping", subtype="command")

    misconfig = [item for item in findings if item.category == "misconfig"]
    cors = next(item for item in misconfig if (item.evidence or {}).get("subtype") == "cors")
    assert cors.status == "confirmed"
    assert "GET /api/widget/config" in cors.evidence["affected_endpoints"]
    assert "GET /api/widget/config-safe" not in cors.evidence["affected_endpoints"]
    assert any((item.evidence or {}).get("subtype") == "headers" for item in misconfig)

    assert has("resource_limits", status="confirmed", endpoint="GET /api/feed")
    assert not has("resource_limits", endpoint="GET /api/feed/safe")
    assert has("resource_limits", status="potential", subtype="rate_headers")

    assert has("inventory", status="confirmed", endpoint="GET /api/v1/status")
    assert not has("inventory", endpoint="GET /api/v0/status")

    assert has("unsafe_consumption", status="confirmed", endpoint="GET /api/quotes")
    assert not has("unsafe_consumption", endpoint="GET /api/quotes/safe")

    from app.engine.report import render_markdown

    report = render_markdown(stored, findings)
    assert "BOLA" in report
    assert "Argus" in report
    db.close()


def test_mass_assignment_optin_confirms_and_restores(lab_servers):
    import httpx

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    payload = ScanCreate(
        name="mass-assignment",
        target_base_url=lab_servers["lab"],
        scope_confirmed=True,
        discovery_mode="openapi",
        openapi_url=f"{lab_servers['lab']}/openapi.json",
        profiles=[
            AuthProfileIn(
                name="alice",
                role="user",
                type="bearer",
                username="alice",
                password="alice123",
                login_path="/api/login",
            ),
        ],
        checks=["mass_assignment"],
        concurrency=4,
        rate_limit_rps=40,
        collaborator_base_url=lab_servers["collaborator"],
    )
    scan = create_scan(db, payload)
    asyncio.run(execute_scan(db, scan.id))
    db.expire_all()
    stored = db.get(type(scan), scan.id)
    assert stored.status == "completed", stored.error_message
    findings = db.query(Finding).filter(Finding.scan_id == stored.id).all()
    categories = {(f.category, f.endpoint_label) for f in findings}
    assert ("mass_assignment", "PATCH /api/profile") in categories
    assert ("mass_assignment", "PATCH /api/secure/profile") not in categories

    # The probe must leave alice's role restored to "user".
    token = httpx.post(
        f"{lab_servers['lab']}/api/login",
        json={"username": "alice", "password": "alice123"},
    ).json()["access_token"]
    profile = httpx.get(
        f"{lab_servers['lab']}/api/profile",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert profile["role"] == "user"
    db.close()


def test_business_flow_optin_confirms_repeat_and_skips_idempotent(lab_servers):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    payload = ScanCreate(
        name="business-flow",
        target_base_url=lab_servers["lab"],
        scope_confirmed=True,
        discovery_mode="openapi",
        openapi_url=f"{lab_servers['lab']}/openapi.json",
        profiles=[],
        checks=["business_flow"],
        concurrency=4,
        rate_limit_rps=40,
        collaborator_base_url=lab_servers["collaborator"],
    )
    scan = create_scan(db, payload)
    asyncio.run(execute_scan(db, scan.id))
    db.expire_all()
    stored = db.get(type(scan), scan.id)
    assert stored.status == "completed", stored.error_message
    findings = db.query(Finding).filter(Finding.scan_id == stored.id).all()
    labels = {(item.endpoint_label, item.status) for item in findings if item.category == "business_flow"}
    assert ("POST /api/checkout", "confirmed") in labels
    assert not any(label[0] == "POST /api/checkout/secure" for label in labels)
    db.close()
