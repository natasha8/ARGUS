"""Unrestricted resource consumption (OWASP API4:2023).

Two read-only signals. The page-size probe never asks for more than 40 rows.
Missing rate-limit headers are only a potential finding: their absence is not
proof that the server has no limit.
"""

from app.engine.checks.base import json_list_len, user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, Exchange, FindingDraft, ScanContext

LIMIT_NAMES = {"limit", "page_size", "per_page"}
PROBE_LIMIT = 40
RATE_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after")
REMEDIATION_PAGE = (
    "Cap page size on the server. Do not let the client choose an unbounded number of rows."
)
REMEDIATION_RATE = (
    "Apply a rate limit and return Retry-After or X-RateLimit-* headers so clients can back off."
)


class ResourceLimitsCheck:
    name = "resource_limits"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        sample: Exchange | None = None
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            for name in self._limit_params(endpoint):
                draft, response = await self._page_size(ctx, endpoint, name)
                if sample is None and 200 <= response.status < 300:
                    sample = response
                if draft:
                    findings.append(draft)
            if sample is None and not self._limit_params(endpoint):
                response = await self._send(ctx, endpoint.path, None)
                if 200 <= response.status < 300:
                    sample = response
        headers = self._rate_headers(sample)
        if headers:
            findings.append(headers)
        return findings

    def _limit_params(self, endpoint: EndpointSpec) -> list[str]:
        names = []
        for param in endpoint.parameters:
            if param.get("in") != "query":
                continue
            if str(param.get("name", "")).lower() in LIMIT_NAMES:
                names.append(param["name"])
        return names

    async def _send(self, ctx: ScanContext, path: str, params: dict | None) -> Exchange:
        response = await ctx.client.send("GET", path, params=params)
        if response.status in {401, 403}:
            profile = next((item for item in user_profiles(ctx) if item.token or item.auth_type != "bearer"), None)
            if profile is not None:
                response = await ctx.client.send("GET", path, params=params, profile=profile)
        return response

    async def _page_size(
        self, ctx: ScanContext, endpoint: EndpointSpec, name: str
    ) -> tuple[FindingDraft | None, Exchange]:
        response = await self._send(ctx, endpoint.path, {name: PROBE_LIMIT})
        length = json_list_len(response)
        if length != PROBE_LIMIT or response.status >= 400:
            return None, response
        return (
            FindingDraft(
                category="resource_limits",
                severity="medium",
                status="confirmed",
                title="Page size is not capped",
                description=(
                    f"Parameter {name} on {endpoint.label} returned {PROBE_LIMIT} items, "
                    "the same number that was requested. The server did not apply a smaller ceiling."
                ),
                owasp_id="API4:2023",
                remediation=REMEDIATION_PAGE,
                endpoint_key=endpoint.label,
                evidence={
                    "subtype": "page_size",
                    "notes": f"The probe asks for {PROBE_LIMIT} rows and never more.",
                    "requests": [excerpt(response, f"{name}={PROBE_LIMIT}")],
                },
            ),
            response,
        )

    def _rate_headers(self, sample: Exchange | None) -> FindingDraft | None:
        if sample is None or sample.status >= 400:
            return None
        present = [name for name in RATE_HEADERS if sample.headers.get(name)]
        if present:
            return None
        return FindingDraft(
            category="resource_limits",
            severity="low",
            status="potential",
            title="No rate-limit headers on the response",
            description=(
                "A successful response did not include Retry-After or X-RateLimit-* headers. "
                "That is a signal, not proof that requests are unlimited."
            ),
            owasp_id="API4:2023",
            remediation=REMEDIATION_RATE,
            evidence={
                "subtype": "rate_headers",
                "notes": "Header absence is only a potential finding.",
                "requests": [excerpt(sample, "sample response")],
            },
        )
