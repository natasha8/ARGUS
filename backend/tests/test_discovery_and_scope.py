from sqlalchemy import create_engine, text

from app.db.session import ensure_schema
from app.engine.discovery import load_spec_text, parse_manual, parse_spec
from app.engine.safeguards import ScopeError, assert_url_allowed, validate_scan_options


OPENAPI = {
    "openapi": "3.0.3",
    "components": {
        "securitySchemes": {
            "HTTPBearer": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "Login": {
                "type": "object",
                "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
            }
        }
    },
    "paths": {
        "/api/orders/{order_id}": {
            "get": {
                "tags": ["orders"],
                "security": [{"HTTPBearer": []}],
                "parameters": [
                    {"name": "order_id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/login": {
            "post": {
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}
                }
            }
        },
    },
}

SWAGGER = {
    "swagger": "2.0",
    "securityDefinitions": {
        "apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
    },
    "paths": {
        "/api/products/search": {
            "get": {
                "security": [{"apiKey": []}],
                "parameters": [{"name": "q", "in": "query", "type": "string", "required": True}],
            }
        }
    },
}


def test_openapi_resolves_security_and_refs():
    endpoints = parse_spec(OPENAPI)
    orders = next(item for item in endpoints if item.path == "/api/orders/{order_id}")
    login = next(item for item in endpoints if item.path == "/api/login")
    assert orders.auth_required is True
    assert orders.parameters[0]["name"] == "order_id"
    assert orders.security["schemes"][0]["name"] == "HTTPBearer"
    assert orders.security["schemes"][0]["scheme"] == "bearer"
    assert login.auth_required is False
    assert login.security["schemes"] == []
    assert login.request_body["properties"][0]["name"] == "username"


def test_swagger_query_parameter():
    endpoints = parse_spec(SWAGGER)
    assert endpoints[0].parameters[0]["in"] == "query"
    assert endpoints[0].parameters[0]["name"] == "q"
    scheme = endpoints[0].security["schemes"][0]
    assert scheme["type"] == "apiKey"
    assert scheme["location"] == "header"
    assert scheme["param_name"] == "X-API-Key"


def test_yaml_and_json_spec_text():
    document = load_spec_text("openapi: 3.0.3\npaths:\n  /health:\n    get: {}\n")
    assert "/health" in document["paths"]
    document = load_spec_text('{"openapi": "3.0.3", "paths": {"/health": {"get": {}}}}')
    assert document["paths"]["/health"]["get"] == {}
    try:
        load_spec_text("just a sentence")
    except ValueError as exc:
        assert "paths" in str(exc)
    else:
        raise AssertionError("text without paths was accepted")


def test_manual_keeps_security_schemes():
    endpoints = parse_manual(
        [
            {
                "method": "GET",
                "path": "/api/keys/ping",
                "auth_required": True,
                "security": {
                    "requirements": [[{"name": "apiKey", "scopes": []}]],
                    "schemes": [
                        {
                            "name": "apiKey",
                            "type": "apiKey",
                            "location": "header",
                            "param_name": "X-API-Key",
                        }
                    ],
                },
            }
        ]
    )
    assert endpoints[0].security["schemes"][0]["param_name"] == "X-API-Key"


def test_existing_database_gains_security_column():
    bind = create_engine("sqlite://")
    with bind.begin() as connection:
        connection.execute(text("CREATE TABLE endpoints (id VARCHAR(36) PRIMARY KEY)"))
    ensure_schema(bind)
    from sqlalchemy import inspect

    columns = {column["name"] for column in inspect(bind).get_columns("endpoints")}
    assert "security" in columns
    ensure_schema(bind)


def test_manual_requires_slash():
    try:
        parse_manual([{"method": "GET", "path": "orders"}])
    except ValueError as exc:
        assert "path" in str(exc).lower() or "/" in str(exc)
    else:
        raise AssertionError("path without a slash was accepted")


def test_scope_blocks_metadata_and_unknown_hosts():
    try:
        assert_url_allowed("http://169.254.169.254/latest")
    except ScopeError:
        pass
    else:
        raise AssertionError("metadata host was allowed")
    try:
        assert_url_allowed("http://example.com")
    except ScopeError:
        pass
    else:
        raise AssertionError("external host was allowed")
    assert assert_url_allowed("http://127.0.0.1:8001/api").startswith("http://127.0.0.1")


def test_scope_requires_confirmation_and_bounds():
    try:
        validate_scan_options(
            target_base_url="http://127.0.0.1:8001",
            scope_confirmed=False,
            checks=["bola"],
            concurrency=4,
            rate_limit_rps=5,
            openapi_url=None,
        )
    except ScopeError:
        pass
    else:
        raise AssertionError("unconfirmed scan was accepted")
    try:
        validate_scan_options(
            target_base_url="http://127.0.0.1:8001",
            scope_confirmed=True,
            checks=["bola"],
            concurrency=4,
            rate_limit_rps=100,
            openapi_url=None,
        )
    except ScopeError:
        pass
    else:
        raise AssertionError("excessive rate limit was accepted")
