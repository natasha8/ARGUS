"""Shared helpers for check modules."""

import re
from typing import Any

from app.engine.types import EndpointSpec, Exchange, Profile, ScanContext

PATH_PARAM = re.compile(r"{([^}]+)}")
ADMIN_HINTS = {"admin", "manage", "internal", "staff", "audit", "superuser"}
READ_METHODS = {"GET", "HEAD"}
SEARCH_HINTS = ("search", "find", "query", "filter", "login", "items")


def fill_path(path: str, values: dict[str, str]) -> str | None:
    names = PATH_PARAM.findall(path)
    if any(name not in values for name in names):
        return None

    def replace(match: re.Match[str]) -> str:
        return values[match.group(1)]

    return PATH_PARAM.sub(replace, path)


def path_param_names(path: str) -> list[str]:
    return PATH_PARAM.findall(path)


def concrete_paths(endpoint: EndpointSpec, probes: list[int]) -> list[str]:
    names = path_param_names(endpoint.path)
    if not names:
        return [endpoint.path]
    paths = []
    for probe in probes:
        filled = fill_path(endpoint.path, {name: str(probe) for name in names})
        if filled:
            paths.append(filled)
    return paths


def parent_collection_path(path: str) -> str | None:
    if "{" not in path:
        return None
    parts = path.rstrip("/").split("/")
    if "{" not in parts[-1]:
        return None
    parent = "/".join(parts[:-1])
    return parent or None


def looks_admin(endpoint: EndpointSpec) -> bool:
    if any(hint in tag.lower() for tag in endpoint.tags for hint in ADMIN_HINTS):
        return True
    parts = [part.lower() for part in endpoint.path.split("/") if part and "{" not in part]
    return any(part in ADMIN_HINTS or part.startswith("admin") for part in parts)


def user_profiles(ctx: ScanContext) -> list[Profile]:
    return [profile for profile in ctx.profiles if profile.auth_type != "none"]


def find_owner(data: Any, depth: int = 0) -> str | None:
    if depth > 4:
        return None
    keys = ("owner", "owner_id", "user", "user_id", "username", "sub", "account")
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                return str(value)
        for value in data.values():
            found = find_owner(value, depth + 1)
            if found:
                return found
    return None


def find_ids(data: Any, depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    found: list[str] = []
    if isinstance(data, list):
        for item in data:
            found.extend(find_ids(item, depth + 1))
    elif isinstance(data, dict):
        if "id" in data and isinstance(data["id"], (str, int)) and not isinstance(data["id"], bool):
            found.append(str(data["id"]))
        for value in data.values():
            found.extend(find_ids(value, depth + 1))
    return found


def json_list_len(exchange: Exchange) -> int | None:
    data = exchange.json_body
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("results", "items", "data", "records"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
    return None


def allows_active_probe(endpoint: EndpointSpec) -> bool:
    """Read-oriented methods only. POST is limited to search-like paths."""
    if endpoint.method in READ_METHODS:
        return True
    if endpoint.method == "POST" and any(hint in endpoint.path.lower() for hint in SEARCH_HINTS):
        return True
    return False
