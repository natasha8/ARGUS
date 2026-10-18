"""Unsafe consumption of APIs (OWASP API10:2023).

The probe sends only the configured collaborator URL, on a parameter named
provider. The finding is confirmed when the target copies the collaborator's
marker into its own response.
"""

from uuid import uuid4

from app.engine.checks.base import user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, ScanContext

PROVIDER_NAMES = {"provider"}
REMEDIATION = (
    "Do not trust fields from an upstream response without validation. "
    "Allowlist the upstream host and ignore unexpected properties."
)


class UnsafeConsumptionCheck:
    name = "unsafe_consumption"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        if not ctx.collaborator_base_url:
            return []
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            for name in self._providers(endpoint):
                draft = await self._probe(ctx, endpoint, name)
                if draft:
                    findings.append(draft)
        return findings

    def _providers(self, endpoint: EndpointSpec) -> list[str]:
        names = []
        for param in endpoint.parameters:
            if param.get("in") == "query" and str(param.get("name", "")).lower() in PROVIDER_NAMES:
                names.append(param["name"])
        return names

    async def _probe(self, ctx: ScanContext, endpoint: EndpointSpec, name: str) -> FindingDraft | None:
        token = uuid4().hex
        marker = f"ARGUS-TRUST-{token}"
        upstream = f"{ctx.collaborator_base_url.rstrip('/')}/trust/{token}"
        response = await ctx.client.send("GET", endpoint.path, params={name: upstream})
        if response.status in {401, 403}:
            profile = next((item for item in user_profiles(ctx) if item.token or item.auth_type != "bearer"), None)
            if profile is not None:
                response = await ctx.client.send(
                    "GET", endpoint.path, params={name: upstream}, profile=profile
                )
        if marker not in response.body_text:
            return None
        return FindingDraft(
            category="unsafe_consumption",
            severity="high",
            status="confirmed",
            title="Upstream response is copied into the API result",
            description=(
                f"Parameter {name} on {endpoint.label} makes the server call the supplied URL "
                "and copy the upstream marker into its own response."
            ),
            owasp_id="API10:2023",
            remediation=REMEDIATION,
            endpoint_key=endpoint.label,
            evidence={
                "notes": "Confirmed because the collaborator marker was reflected by the target, not only requested.",
                "requests": [excerpt(response, f"parameter {name}")],
            },
        )
