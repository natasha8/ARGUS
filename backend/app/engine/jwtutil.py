"""Minimal JWT helpers for detection. Not a general-purpose JWT library."""

import base64
import hashlib
import hmac
import json
from typing import Any

COMMON_SECRETS = (
    "secret",
    "password",
    "changeme",
    "jwt-secret",
    "supersecret",
    "secret123",
)


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def split_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    signature = parts[2] if len(parts) > 2 else ""
    return header, payload, signature


def peek_subject(token: str) -> str | None:
    parsed = split_jwt(token)
    if not parsed:
        return None
    subject = parsed[1].get("sub")
    return str(subject) if subject is not None else None


def forge_none(payload: dict[str, Any]) -> str:
    header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def sign_hs256(payload: dict[str, Any], secret: str) -> str:
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    digest = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url_encode(digest)}"


def matching_secret(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    try:
        expected = b64url_decode(parts[2])
    except Exception:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in COMMON_SECRETS:
        digest = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(digest, expected):
            return secret
    return None
