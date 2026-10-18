"""OpenAPI 3 and Swagger 2 discovery."""

from typing import Any

import yaml

from app.engine.types import EndpointSpec

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head"}


def _resolve_ref(document: dict[str, Any], schema: Any, depth: int = 0) -> dict[str, Any]:
    if depth > 8 or not isinstance(schema, dict):
        return schema if isinstance(schema, dict) else {}
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return schema
    node: Any = document
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return schema
        node = node[part]
    if isinstance(node, dict):
        merged = dict(node)
        return _resolve_ref(document, merged, depth + 1)
    return schema


def _schema_type(schema: dict[str, Any] | None) -> str:
    if not schema:
        return "string"
    raw = schema.get("type")
    if isinstance(raw, list):
        raw = next((item for item in raw if item != "null"), "string")
    if isinstance(raw, str):
        return raw
    if "properties" in schema:
        return "object"
    return "string"


def empty_security() -> dict[str, Any]:
    return {"requirements": [], "schemes": []}


def normalize_security(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return empty_security()
    requirements = value.get("requirements")
    schemes = value.get("schemes")
    return {
        "requirements": requirements if isinstance(requirements, list) else [],
        "schemes": schemes if isinstance(schemes, list) else [],
    }


def load_spec_text(text: str) -> dict[str, Any]:
    """Parse an OpenAPI or Swagger document from JSON or YAML text."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("The specification file is empty.")
    try:
        document = yaml.safe_load(stripped)
    except yaml.YAMLError as exc:
        raise ValueError("The specification is not valid JSON or YAML.") from exc
    if not isinstance(document, dict) or "paths" not in document:
        raise ValueError("The specification must be an OpenAPI or Swagger object with paths.")
    return document


def _scheme_catalog(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw: dict[str, Any] = {}
    components = document.get("components") or {}
    if isinstance(components, dict):
        schemes = components.get("securitySchemes") or {}
        if isinstance(schemes, dict):
            raw.update(schemes)
    definitions = document.get("securityDefinitions") or {}
    if isinstance(definitions, dict):
        raw.update(definitions)
    catalog: dict[str, dict[str, Any]] = {}
    for name, spec in raw.items():
        resolved = _resolve_ref(document, spec)
        if not isinstance(resolved, dict):
            resolved = {}
        catalog[name] = {
            "name": name,
            "type": resolved.get("type"),
            "scheme": resolved.get("scheme"),
            "location": resolved.get("in"),
            "param_name": resolved.get("name"),
        }
    return catalog


def _security(document: dict[str, Any], operation: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Return whether the operation requires auth, and the schemes it names.

    An operation inherits the document-level `security` list. An empty list is
    explicit public access. Scheme objects come from OpenAPI `securitySchemes`
    or Swagger `securityDefinitions`.
    """
    declared = operation.get("security", None)
    if declared is None:
        declared = document.get("security") or []
    if not isinstance(declared, list):
        declared = []
    catalog = _scheme_catalog(document)
    requirements: list[list[dict[str, Any]]] = []
    schemes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for requirement in declared:
        if not isinstance(requirement, dict):
            continue
        group: list[dict[str, Any]] = []
        for name, scopes in requirement.items():
            scope_list = list(scopes) if isinstance(scopes, list) else []
            group.append({"name": str(name), "scopes": scope_list})
            if name not in seen:
                seen.add(name)
                described = dict(catalog.get(name) or {
                    "name": name,
                    "type": None,
                    "scheme": None,
                    "location": None,
                    "param_name": None,
                })
                described.pop("scopes", None)
                schemes.append(described)
        requirements.append(group)
    return bool(declared), {"requirements": requirements, "schemes": schemes}


def _parameters(document: dict[str, Any], operation: dict[str, Any], path_item: dict[str, Any]) -> tuple[list[dict], dict | None]:
    parameters: list[dict[str, Any]] = []
    request_body: dict[str, Any] | None = None
    combined = list(path_item.get("parameters") or []) + list(operation.get("parameters") or [])
    for raw in combined:
        param = _resolve_ref(document, raw)
        location = param.get("in", "query")
        if location == "body":
            schema = _resolve_ref(document, param.get("schema") or {})
            request_body = _body_from_schema(document, schema)
            continue
        if "name" not in param:
            continue
        schema = _resolve_ref(document, param.get("schema") or {})
        if not schema and param.get("type"):
            schema = {"type": param.get("type")}
        parameters.append(
            {
                "name": param["name"],
                "in": location,
                "schema_type": _schema_type(schema),
                "required": bool(param.get("required", location == "path")),
            }
        )
    if request_body is None and operation.get("requestBody"):
        body = operation["requestBody"]
        content = (body.get("content") or {}).get("application/json") or {}
        schema = _resolve_ref(document, content.get("schema") or {})
        request_body = _body_from_schema(document, schema)
    return parameters, request_body


def _body_from_schema(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any] | None:
    if not schema:
        return None
    properties = []
    for name, prop in (schema.get("properties") or {}).items():
        resolved = _resolve_ref(document, prop)
        properties.append({"name": name, "schema_type": _schema_type(resolved)})
    return {"content_type": "application/json", "properties": properties}


def parse_spec(document: dict[str, Any]) -> list[EndpointSpec]:
    if not isinstance(document, dict) or "paths" not in document:
        raise ValueError("The document has no 'paths'. OpenAPI 3 or Swagger 2 is required.")
    endpoints: list[EndpointSpec] = []
    for path, path_item in (document.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters, request_body = _parameters(document, operation, path_item)
            auth_required, security = _security(document, operation)
            endpoints.append(
                EndpointSpec(
                    method=method.upper(),
                    path=path,
                    parameters=parameters,
                    request_body=request_body,
                    tags=list(operation.get("tags") or []),
                    auth_required=auth_required,
                    security=security,
                )
            )
    return endpoints
