"""Improper inventory management (OWASP API9:2023).

From versions declared in the specification, Argus requests only the previous
integer version. It does not use a path wordlist. A 404 is not a finding.
"""

import re

from app.engine.checks.base import user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, ScanContext

VERSION = re.compile(r"/v(\d+)(?=/|$)")
REMEDIATION = (
    "Retire old versions, or require the same authentication and authorization as the current one. "
    "Do not leave an undocumented version reachable."
)


def previous_version(path: str) -> str | None:
    match = VERSION.search(path)
    if not match:
        return None
    current = int(match.group(1))
    if current < 2:
        return None
    return path[: match.start(1)] + str(current - 1) + path[match.end(1) :]


class InventoryCheck:
    name = "inventory"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        known = {endpoint.path for endpoint in ctx.endpoints}
        findings: list[FindingDraft] = []
        probed: set[str] = set()
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            candidate = previous_version(endpoint.path)
            if not candidate or candidate in known or candidate in probed:
                continue
            probed.add(candidate)
            draft = await self._probe(ctx, endpoint, candidate)
            if draft:
                findings.append(draft)
        return findings

    async def _probe(self, ctx: ScanContext, endpoint: EndpointSpec, path: str) -> FindingDraft | None:
        response = await ctx.client.send("GET", path)
        if response.status in {401, 403}:
            profile = next((item for item in user_profiles(ctx) if item.token or item.auth_type != "bearer"), None)
            if profile is not None:
                response = await ctx.client.send("GET", path, profile=profile)
        if response.status < 200 or response.status >= 300:
            return None
        label = f"GET {path}"
        return FindingDraft(
            category="inventory",
            severity="medium",
            status="confirmed",
            title="Undocumented previous API version is reachable",
            description=(
                f"{label} is not in the specification, but it responds successfully. "
                f"It was derived from {endpoint.label} by stepping the version number down by one."
            ),
            owasp_id="API9:2023", owasp_web="A02:2025",
            remediation=REMEDIATION,
            endpoint_key=label,
            evidence={
                "notes": "Only the previous integer version is requested. Missing paths that return 404 are ignored.",
                "requests": [excerpt(response, "previous version")],
            },
        )
