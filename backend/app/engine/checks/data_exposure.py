"""Excessive data exposure (OWASP API3:2023), the read side of broken object properties.

Argus looks for sensitive properties that an authenticated GET returns to the
client. Mass assignment, the write side, lives in `mass_assignment.py` and stays
off unless that check is selected, because it changes server state and then restores it.
"""

import json
import re

from app.engine.checks.base import concrete_paths, user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, ScanContext

REMEDIATION = (
    "Return only the properties the client needs. Serialize responses with an explicit "
    "allowlist of fields instead of dumping the whole object, and never expose secrets, "
    "password hashes, or reset tokens."
)

# Strong indicators: a property name that should never reach a client.
SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "passwordhash",
    "pwd_hash",
    "secret",
    "secret_key",
    "private_key",
    "privatekey",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "reset_token",
    "password_reset_token",
    "salt",
    "mfa_secret",
    "totp_secret",
}
# Weaker indicators: often legitimate (login responses), so only flagged as potential.
WEAK_KEYS = {"token", "api_key", "apikey", "access_key", "refresh_token"}
HASH_FIELDS = {"password", "password_hash", "passwordhash", "pwd_hash"}
SALT_KEYS = {"salt", "password_salt", "pwd_salt", "hash_salt"}
FAST_HASH = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_DIGEST = re.compile(r"[0-9a-fA-F]+\Z")


def _sensitive_hits(data, keys: set[str], depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in keys:
                if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value):
                    found.append(key)
            found.extend(_sensitive_hits(value, keys, depth + 1))
    elif isinstance(data, list):
        for item in data:
            found.extend(_sensitive_hits(item, keys, depth + 1))
    return found


def _fast_hashes(data, depth: int = 0) -> list[dict[str, str]]:
    """Name unsalted MD5, SHA-1, and SHA-256 digests. The digest itself is not returned."""
    if depth > 5 or not isinstance(data, (dict, list)):
        return []
    found: list[dict[str, str]] = []
    if isinstance(data, dict):
        salted = any(
            isinstance(key, str) and key.lower() in SALT_KEYS and value not in (None, "")
            for key, value in data.items()
        )
        for key, value in data.items():
            if (
                isinstance(key, str)
                and key.lower() in HASH_FIELDS
                and isinstance(value, str)
                and not salted
                and HEX_DIGEST.fullmatch(value)
                and len(value) in FAST_HASH
            ):
                found.append({"field": key, "algorithm": FAST_HASH[len(value)]})
            found.extend(_fast_hashes(value, depth + 1))
    else:
        for item in data:
            found.extend(_fast_hashes(item, depth + 1))
    return found


def _redact(data, keys: set[str], depth: int = 0):
    if depth > 5:
        return data
    if isinstance(data, dict):
        return {
            key: ("[redacted]" if isinstance(key, str) and key.lower() in keys else _redact(value, keys, depth + 1))
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [_redact(item, keys, depth + 1) for item in data]
    return data


class DataExposureCheck:
    name = "data_exposure"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        profile = next(
            (item for item in user_profiles(ctx) if item.auth_type != "bearer" or item.token),
            None,
        )
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            draft = await self._probe(ctx, endpoint, profile)
            if draft is not None:
                findings.append(draft)
        return findings

    async def _probe(self, ctx: ScanContext, endpoint: EndpointSpec, profile) -> FindingDraft | None:
        for path in concrete_paths(endpoint, ctx.id_probes)[:2]:
            response = await ctx.client.send("GET", path, profile=profile)
            if response.status >= 400 or response.json_body is None:
                continue
            strong = sorted(set(_sensitive_hits(response.json_body, SENSITIVE_KEYS)))
            weak = sorted(set(_sensitive_hits(response.json_body, WEAK_KEYS)))
            if strong:
                return self._finding(endpoint, response, strong, "confirmed", "high")
            if weak:
                return self._finding(endpoint, response, weak, "potential", "medium")
        return None

    def _finding(self, endpoint, response, keys: list[str], status: str, severity: str) -> FindingDraft:
        label = "Sensitive properties exposed" if status == "confirmed" else "Possibly sensitive properties exposed"
        joined = ", ".join(keys)
        fast = _fast_hashes(response.json_body) if status == "confirmed" else []
        request = excerpt(response, "authenticated read")
        redacted = _redact(response.json_body, SENSITIVE_KEYS | WEAK_KEYS)
        request["body_excerpt"] = json.dumps(redacted, ensure_ascii=False)[:1200]
        hash_note = ""
        if fast:
            described = ", ".join(f"{item['field']} ({item['algorithm']})" for item in fast)
            hash_note = f" {described} matches an unsalted fast digest. The digest is not stored."
        notes = (
            "Values are not copied into the report. Only the field names are listed." + hash_note
            if status == "confirmed"
            else "These field names are sometimes legitimate; review the response by hand."
        )
        evidence: dict = {
            "subtype": "excessive_data_exposure",
            "exposed_fields": keys,
            "notes": notes,
            "requests": [request],
        }
        if fast:
            evidence["fast_hashes"] = fast
        return FindingDraft(
            category="data_exposure",
            severity=severity,
            status=status,
            title=f"{label} in {endpoint.label}",
            description=(
                f"The response from {endpoint.label} includes the field(s) {joined}, which a client "
                "should not receive. The API appears to serialize the whole object instead of an allowlist."
            ),
            owasp_id="API3:2023",
            owasp_web="A04:2025",
            remediation=REMEDIATION,
            endpoint_key=endpoint.label,
            evidence=evidence,
        )
