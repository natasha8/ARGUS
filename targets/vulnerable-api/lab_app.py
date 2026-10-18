"""Local training API. Intentionally vulnerable. Do not expose beyond localhost."""

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict

SECRET = "secret"
BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.internal"}

USERS = {
    "alice": {"password": "alice123", "role": "user"},
    "bob": {"password": "bob123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}
ORDERS = [
    {"id": 101, "owner": "alice", "item": "Laptop"},
    {"id": 102, "owner": "bob", "item": "Camera"},
]
ITEMS = [{"name": "notebook"}, {"name": "camera"}, {"name": "keyboard"}]
PROFILES = {
    name: {
        "username": name,
        "display_name": name.title(),
        "role": info["role"],
        "password_hash": hashlib.sha256(info["password"].encode()).hexdigest(),
        "reset_token": f"lab-reset-{name}",
    }
    for name, info in USERS.items()
}
PUBLIC_PROFILE_FIELDS = ("username", "display_name", "role")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
_db.executemany(
    "INSERT INTO products (name) VALUES (?)",
    [("notebook",), ("camera",), ("keyboard",)],
)
_db.commit()

app = FastAPI(
    title="Argus Lab API",
    version="1.0.0",
    description="Local training target. Intentionally vulnerable. Do not expose it.",
)
bearer_scheme = HTTPBearer(auto_error=True)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_token(sub: str, role: str) -> str:
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = {"sub": sub, "role": role, "exp": int(time.time()) + 3600}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    digest = hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64encode(digest)}"


def _parts(token: str) -> tuple[dict, dict, list[str]]:
    parts = token.split(".")
    if len(parts) < 2:
        raise HTTPException(status_code=401, detail="malformed token")
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="malformed token") from exc
    return header, payload, parts


def decode_loose(token: str) -> dict:
    """Lab vulnerability: accepts alg=none and ignores exp."""
    header, payload, parts = _parts(token)
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        return payload
    if algorithm != "hs256" or len(parts) < 3:
        raise HTTPException(status_code=401, detail="algorithm rejected")
    expected = _b64decode(parts[2])
    digest = hmac.new(SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(digest, expected):
        raise HTTPException(status_code=401, detail="invalid signature")
    return payload


def decode_strict(token: str) -> dict:
    header, payload, parts = _parts(token)
    if str(header.get("alg", "")).lower() != "hs256" or len(parts) < 3:
        raise HTTPException(status_code=401, detail="algorithm rejected")
    expected = _b64decode(parts[2])
    digest = hmac.new(SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(digest, expected):
        raise HTTPException(status_code=401, detail="invalid signature")
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or exp < time.time():
        raise HTTPException(status_code=401, detail="expired token")
    return payload


def loose_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    return decode_loose(credentials.credentials)


def strict_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    return decode_strict(credentials.credentials)


def admin_user(user: dict = Depends(loose_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return user


class LoginBody(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    display_name: str | None = None


class ItemQuery(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: Any


class CheckoutBody(BaseModel):
    sku: str = "notebook"


PURCHASES: list[dict] = []
CHECKOUT_KEYS: dict[str, dict] = {}


def _order(order_id: str) -> dict:
    for order in ORDERS:
        if str(order["id"]) == order_id:
            return order
    raise HTTPException(status_code=404, detail="not found")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "argus-lab"}


@app.post("/api/login")
def login(body: LoginBody) -> dict:
    user = USERS.get(body.username)
    if user is None or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {
        "access_token": issue_token(body.username, user["role"]),
        "token_type": "bearer",
        "sub": body.username,
        "role": user["role"],
    }


@app.get("/api/account")
def account(user: dict = Depends(loose_user)) -> dict:
    return {"sub": user.get("sub"), "role": user.get("role")}


@app.get("/api/secure/me")
def secure_me(user: dict = Depends(strict_user)) -> dict:
    return {"sub": user.get("sub"), "role": user.get("role")}


def _profile(user: dict) -> dict:
    profile = PROFILES.get(str(user.get("sub")))
    if profile is None:
        raise HTTPException(status_code=404, detail="not found")
    return profile


@app.get("/api/profile")
def get_profile(user: dict = Depends(loose_user)) -> dict:
    # Vulnerability: returns internal fields such as the password hash.
    return dict(_profile(user))


@app.patch("/api/profile")
def update_profile(body: dict[str, Any], user: dict = Depends(loose_user)) -> dict:
    # Vulnerability: every property in the body is written, including role.
    profile = _profile(user)
    for key, value in body.items():
        if key in profile and key != "username":
            profile[key] = value
    return dict(profile)


@app.get("/api/secure/profile")
def get_profile_secure(user: dict = Depends(strict_user)) -> dict:
    profile = _profile(user)
    return {key: profile[key] for key in PUBLIC_PROFILE_FIELDS}


@app.patch("/api/secure/profile")
def update_profile_secure(body: ProfileUpdate, user: dict = Depends(strict_user)) -> dict:
    profile = _profile(user)
    if body.display_name is not None:
        profile["display_name"] = body.display_name
    return {key: profile[key] for key in PUBLIC_PROFILE_FIELDS}


@app.get("/api/orders")
def list_orders(user: dict = Depends(loose_user)) -> list[dict]:
    return [order for order in ORDERS if order["owner"] == user.get("sub")]


@app.get("/api/orders/{order_id}")
def get_order(order_id: str, user: dict = Depends(loose_user)) -> dict:
    # Vulnerability: any authenticated user can read any order.
    del user
    return _order(order_id)


@app.get("/api/orders/{order_id}/secure")
def get_order_secure(order_id: str, user: dict = Depends(loose_user)) -> dict:
    order = _order(order_id)
    if order["owner"] != user.get("sub"):
        raise HTTPException(status_code=403, detail="forbidden")
    return order


@app.get("/api/admin/users", tags=["admin"])
def admin_users(user: dict = Depends(loose_user)) -> list[dict]:
    # Vulnerability: the admin path does not check the role.
    del user
    return [{"username": name, "role": info["role"]} for name, info in USERS.items()]


@app.get("/api/admin/audit", tags=["admin"])
def admin_audit(user: dict = Depends(admin_user)) -> dict:
    return {"events": [{"actor": user.get("sub"), "action": "audit"}]}


@app.get("/api/preview")
async def preview(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="http only")
    if host in BLOCKED_HOSTS or host.startswith("169.254."):
        raise HTTPException(status_code=400, detail="host blocked")
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="fetch failed") from exc
    return {"status": response.status_code, "body": response.text[:2000]}


@app.get("/api/products/search")
def search_products(q: str) -> dict:
    query = f"SELECT id, name FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = _db.execute(query).fetchall()
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"sqlite3.OperationalError: {exc}") from exc
    return {"results": [{"id": row["id"], "name": row["name"]} for row in rows]}


@app.get("/api/products/search-safe")
def search_products_safe(q: str) -> dict:
    rows = _db.execute(
        "SELECT id, name FROM products WHERE name LIKE ?",
        (f"%{q}%",),
    ).fetchall()
    return {"results": [{"id": row["id"], "name": row["name"]} for row in rows]}


@app.post("/api/items/find")
def find_items(payload: ItemQuery) -> dict:
    """Lab interpreter: user-controlled operators are applied to the item name."""
    name = payload.name
    if isinstance(name, dict) and "$gt" in name:
        matched = [item for item in ITEMS if item["name"] > str(name.get("$gt", ""))]
        return {"items": matched}
    if isinstance(name, str):
        return {"items": [item for item in ITEMS if item["name"] == name]}
    return {"items": []}


@app.get("/api/diag/ping")
def ping(host: str) -> dict:
    """Lab stand-in for a shell sink. It does not spawn a shell.

    Metacharacters return a shell-style error so the scanner can show the
    detection logic without executing commands.
    """
    if any(character in host for character in "'\"`;|&$()"):
        return {"output": "sh: syntax error: unmatched quote", "code": 2}
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host or ""):
        return {"output": "sh: syntax error: unexpected token", "code": 2}
    return {"output": f"pong {host}", "code": 0}


@app.get("/api/widget/config")
def widget_config(request: Request) -> JSONResponse:
    # Vulnerability: reflects any Origin and allows credentials.
    origin = request.headers.get("origin", "*")
    return JSONResponse(
        {"widget": "chat", "theme": "dark"},
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
    )


@app.get("/api/widget/config-safe")
def widget_config_safe() -> JSONResponse:
    # Safe: a single fixed, trusted origin, no reflection.
    return JSONResponse(
        {"widget": "chat", "theme": "dark"},
        headers={"Access-Control-Allow-Origin": "https://trusted.example"},
    )


@app.get("/api/keys/ping")
def api_key_ping(request: Request) -> dict:
    if request.headers.get("x-api-key") == "lab-key":
        return {"ok": True, "mode": "api_key"}
    raise HTTPException(status_code=401, detail="api key")


@app.get("/api/basic/ping")
def basic_ping(request: Request) -> dict:
    expected = "Basic " + base64.b64encode(b"carol:carol123").decode()
    if request.headers.get("authorization") == expected:
        return {"ok": True, "mode": "basic"}
    raise HTTPException(status_code=401, detail="basic")


async def _fetch_url(url: str) -> httpx.Response:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="http only")
    if host in BLOCKED_HOSTS or host.startswith("169.254."):
        raise HTTPException(status_code=400, detail="host blocked")
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            return await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="fetch failed") from exc


@app.get("/api/feed")
def feed(limit: int = 10) -> dict:
    # Vulnerability: the client chooses the page size. The cap at 100 only keeps the lab small.
    size = min(max(limit, 0), 100)
    return {"items": [{"n": index} for index in range(size)]}


@app.get("/api/feed/safe")
def feed_safe(limit: int = 10) -> dict:
    size = min(max(limit, 0), 10)
    return {"items": [{"n": index} for index in range(size)]}


@app.get("/api/v2/status")
def status_v2() -> dict:
    return {"version": 2, "status": "current"}


@app.get("/api/v1/status", include_in_schema=False)
def status_v1() -> dict:
    # Vulnerability: the previous version is still served and is omitted from the specification.
    return {"version": 1, "status": "deprecated", "debug": True}


@app.get("/api/quotes")
async def quotes(provider: str) -> dict:
    # Vulnerability: the upstream JSON is copied into the API response.
    response = await _fetch_url(provider)
    try:
        data = response.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {"price": data.get("price"), "marker": data.get("marker")}


@app.get("/api/quotes/safe")
async def quotes_safe(provider: str) -> dict:
    await _fetch_url(provider)
    return {"ok": True}


_REPORT = {"format": "json", "rows": [{"sku": "notebook", "total": 1}]}


@app.get("/api/reports/export")
def export_report(format: str | None = None) -> dict:
    # Vulnerability: the specification marks format as required, but a missing value still returns the report.
    del format
    return dict(_REPORT)


@app.get("/api/reports/export/safe")
def export_report_safe(format: str) -> dict:
    if format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="format required")
    return {"format": format, "rows": [{"sku": "notebook", "total": 1}]}


def _openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    operation = (schema.get("paths") or {}).get("/api/reports/export", {}).get("get")
    if operation:
        for param in operation.get("parameters") or []:
            if param.get("name") == "format":
                param["required"] = True
    app.openapi_schema = schema
    return schema


app.openapi = _openapi


@app.post("/api/checkout")
def checkout(body: CheckoutBody) -> dict:
    # Vulnerability: the same purchase is created again. The idempotency key is ignored.
    PURCHASES.append({"sku": body.sku})
    return {"id": len(PURCHASES), "sku": body.sku, "count": len(PURCHASES)}


@app.post("/api/checkout/secure")
def checkout_secure(
    body: CheckoutBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict:
    if idempotency_key and idempotency_key in CHECKOUT_KEYS:
        return CHECKOUT_KEYS[idempotency_key]
    PURCHASES.append({"sku": body.sku})
    record = {"id": len(PURCHASES), "sku": body.sku, "count": len(PURCHASES)}
    if idempotency_key:
        CHECKOUT_KEYS[idempotency_key] = record
    return record
