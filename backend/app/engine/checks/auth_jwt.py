"""JWT authentication checks: weak HMAC secret, alg none, ignored expiry, forged claims."""

import time

from app.engine.checks.base import concrete_paths, looks_admin
from app.engine.http import excerpt
from app.engine.jwtutil import forge_none, matching_secret, sign_hs256, split_jwt
from app.engine.types import FindingDraft, Profile, ScanContext

REMEDIATION = (
    "Reject the none algorithm, always verify the signature with a long random secret, "
    "and reject expired tokens. Do not accept an algorithm declared by the token unless it is on your allowlist."
)


class AuthJwtCheck:
    name = "auth_jwt"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        profile = next(
            (item for item in ctx.profiles if item.auth_type == "bearer" and item.token),
            None,
        )
        if profile is None or profile.token is None:
            return []
        parsed = split_jwt(profile.token)
        if parsed is None:
            return []
        _header, payload, _signature = parsed
        findings: list[FindingDraft] = []
        secret = matching_secret(profile.token)
        if secret:
            findings.append(
                FindingDraft(
                    category="auth_jwt",
                    severity="high",
                    status="confirmed",
                    title="JWT signed with a weak secret",
                    description=(
                        "The token's HMAC signature matches a very common secret. "
                        "Anyone who guesses it can mint arbitrary tokens."
                    ),
                    owasp_id="API2:2023", owasp_web="A07:2025",
                    remediation=REMEDIATION,
                    evidence={
                        "notes": "The secret was compared locally with a short list of obvious values. It is not printed in the report.",
                        "requests": [],
                        "secret_recovered": True,
                    },
                )
            )
        none_token = forge_none(payload)
        expired_token = None
        if secret:
            expired_payload = dict(payload)
            expired_payload["exp"] = int(time.time()) - 3600
            expired_token = sign_hs256(expired_payload, secret)

        none_hits: list[str] = []
        exp_hits: list[str] = []
        none_evidence = []
        exp_evidence = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET" or not endpoint.auth_required:
                continue
            worked = await self._first_ok(ctx, endpoint, profile)
            if worked is None:
                continue
            path, baseline, anon = worked
            if anon.status not in {401, 403}:
                continue
            forged = await ctx.client.send(
                "GET",
                path,
                headers={"Authorization": f"Bearer {none_token}"},
            )
            if forged.status < 400:
                none_hits.append(endpoint.label)
                none_evidence.append(excerpt(baseline, "original token"))
                none_evidence.append(excerpt(forged, "alg none"))
            if expired_token:
                expired = await ctx.client.send(
                    "GET",
                    path,
                    headers={"Authorization": f"Bearer {expired_token}"},
                )
                if expired.status < 400:
                    exp_hits.append(endpoint.label)
                    exp_evidence.append(excerpt(expired, "re-signed expired token"))
        if none_hits:
            findings.append(
                FindingDraft(
                    category="auth_jwt",
                    severity="critical",
                    status="confirmed",
                    title="JWT accepted without a valid signature (alg none)",
                    description=(
                        "Some endpoints accept a token with algorithm none and an empty signature. "
                        "The API is not verifying the signature."
                    ),
                    owasp_id="API2:2023", owasp_web="A07:2025",
                    remediation=REMEDIATION,
                    evidence={
                        "notes": "Confirmed only where the real token returns 2xx and the anonymous request returns 401 or 403.",
                        "affected_endpoints": none_hits,
                        "requests": none_evidence[:4],
                    },
                )
            )
        if exp_hits:
            findings.append(
                FindingDraft(
                    category="auth_jwt",
                    severity="high",
                    status="confirmed",
                    title="JWT expiry is not verified",
                    description=(
                        "A token whose exp is in the past, re-signed with the weak secret already identified, "
                        "is still accepted."
                    ),
                    owasp_id="API2:2023", owasp_web="A07:2025",
                    remediation=REMEDIATION,
                    evidence={
                        "notes": "Expiry is not enforced on the listed endpoints.",
                        "affected_endpoints": exp_hits,
                        "requests": exp_evidence[:2],
                    },
                )
            )
        if secret:
            tampered = await self._claim_tampering(ctx, secret)
            if tampered:
                findings.append(tampered)
        return findings

    async def _claim_tampering(self, ctx: ScanContext, secret: str) -> FindingDraft | None:
        low = None
        low_payload = None
        for item in ctx.profiles:
            if item.auth_type != "bearer" or not item.token:
                continue
            parsed = split_jwt(item.token)
            if parsed is None:
                continue
            role = parsed[1].get("role")
            if isinstance(role, str) and role.lower() != "admin":
                low, low_payload = item, parsed[1]
                break
        if low is None or low_payload is None:
            return None
        forged_payload = dict(low_payload)
        forged_payload["role"] = "admin"
        forged_token = sign_hs256(forged_payload, secret)
        hits: list[str] = []
        evidence = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET" or not looks_admin(endpoint):
                continue
            for path in concrete_paths(endpoint, ctx.id_probes)[:1]:
                real = await ctx.client.send("GET", path, profile=low)
                if real.status not in {401, 403}:
                    continue
                forged = await ctx.client.send(
                    "GET",
                    path,
                    headers={"Authorization": f"Bearer {forged_token}"},
                )
                if forged.status < 400:
                    hits.append(endpoint.label)
                    evidence.append(excerpt(real, f"real token, role {low_payload.get('role')}"))
                    evidence.append(excerpt(forged, "re-signed token, role admin"))
        if not hits:
            return None
        return FindingDraft(
            category="auth_jwt",
            severity="critical",
            status="confirmed",
            title="JWT role claim can be forged to escalate privileges",
            description=(
                f"Re-signing the token of profile {low.name} with role admin, using the weak secret "
                "already identified, opens endpoints that reject the real token."
            ),
            owasp_id="API2:2023", owasp_web="A07:2025",
            remediation=REMEDIATION,
            evidence={
                "notes": "Confirmed only where the real low-privilege token gets 401 or 403 and the forged one gets 2xx.",
                "affected_endpoints": hits,
                "requests": evidence[:4],
            },
        )

    async def _first_ok(self, ctx: ScanContext, endpoint, profile: Profile):
        for path in concrete_paths(endpoint, ctx.id_probes):
            baseline = await ctx.client.send("GET", path, profile=profile)
            if baseline.status < 400:
                anon = await ctx.client.send("GET", path, profile=None)
                return path, baseline, anon
        return None
