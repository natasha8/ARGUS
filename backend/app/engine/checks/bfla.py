"""Broken function level authorization on admin-looking routes."""

from app.engine.checks.base import concrete_paths, looks_admin, user_profiles
from app.engine.http import excerpt
from app.engine.types import FindingDraft, ScanContext

REMEDIATION = (
    "Every privileged function must check the role on the server. "
    "Hiding the path is not an access control."
)


class BflaCheck:
    name = "bfla"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        profiles = [profile for profile in user_profiles(ctx) if profile.auth_type != "bearer" or profile.token]
        low = next((profile for profile in profiles if profile.role.lower() != "admin"), None)
        admin = next((profile for profile in profiles if profile.role.lower() == "admin"), None)
        if low is None:
            return []
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET" or not looks_admin(endpoint):
                continue
            paths = concrete_paths(endpoint, ctx.id_probes)
            if not paths:
                continue
            path = paths[0]
            anon = await ctx.client.send("GET", path, profile=None)
            low_resp = await ctx.client.send("GET", path, profile=low)
            admin_resp = None
            if admin is not None:
                admin_resp = await ctx.client.send("GET", path, profile=admin)
            if low_resp.status < 400 and anon.status in {401, 403}:
                if admin_resp is not None and admin_resp.status >= 400:
                    continue
                findings.append(
                    FindingDraft(
                        category="bfla",
                        severity="high",
                        status="confirmed",
                        title="Admin function reachable with insufficient privileges",
                        description=(
                            f"Profile {low.name} (role {low.role}) receives HTTP {low_resp.status} "
                            f"from {endpoint.label}. The anonymous request is rejected."
                        ),
                        owasp_id="API5:2023", owasp_web="A01:2025",
                        remediation=REMEDIATION,
                        endpoint_key=endpoint.label,
                        evidence={
                            "notes": "Confirmed by comparing anonymous, low-privilege, and admin roles when present.",
                            "requests": [
                                excerpt(low_resp, f"role {low.role}"),
                                excerpt(anon, "anonymous"),
                            ],
                        },
                    )
                )
            elif low_resp.status < 400 and anon.status < 400 and endpoint.auth_required:
                findings.append(
                    FindingDraft(
                        category="bfla",
                        severity="critical",
                        status="confirmed",
                        title="Admin function reachable without authentication",
                        description=f"{endpoint.label} succeeds even without credentials.",
                        owasp_id="API5:2023", owasp_web="A01:2025",
                        remediation=REMEDIATION,
                        endpoint_key=endpoint.label,
                        evidence={
                            "notes": "Both the low-privilege role and the anonymous request succeed.",
                            "requests": [excerpt(anon, "anonymous"), excerpt(low_resp, f"role {low.role}")],
                        },
                    )
                )
        return findings
