"""Manual endpoint lists supplied by the user."""

from typing import Any

from app.engine.discovery.openapi import normalize_security
from app.engine.types import EndpointSpec


def parse_manual(items: list[dict[str, Any]] | None) -> list[EndpointSpec]:
    endpoints: list[EndpointSpec] = []
    for item in items or []:
        method = str(item.get("method", "GET")).upper()
        path = str(item.get("path", "")).strip()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise ValueError(f"Unsupported method: {method}")
        if not path.startswith("/"):
            raise ValueError(f"Path must start with /: {path}")
        parameters = []
        for param in item.get("parameters") or []:
            name = param.get("name")
            if not name:
                continue
            parameters.append(
                {
                    "name": name,
                    "in": param.get("in", "query"),
                    "schema_type": param.get("schema_type", "string"),
                    "required": bool(param.get("required", param.get("in") == "path")),
                }
            )
        endpoints.append(
            EndpointSpec(
                method=method,
                path=path,
                parameters=parameters,
                request_body=item.get("request_body"),
                tags=list(item.get("tags") or []),
                auth_required=bool(item.get("auth_required", True)),
                security=normalize_security(item.get("security")),
            )
        )
    return endpoints
