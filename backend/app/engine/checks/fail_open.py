"""Fail-open when a required query parameter is omitted (OWASP A10:2025).

GET only. Sends the documented request once, then the same request without one
required query parameter. Confirmed when both succeed and the body is unchanged.
A 4xx on the omitted call is ignored.
"""

from app.engine.checks.base import user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, Exchange, FindingDraft, ScanContext

PLACEHOLDERS = {
    "string": "json",
    "integer": "1",
    "number": "1",
    "boolean": "true",
}
REMEDIATION = (
    "Reject a request that omits a required parameter. Return 4xx instead of continuing "
    "with a default that still produces the successful response."
)


def _placeholder(param: dict) -> str:
    return PLACEHOLDERS.get(str(param.get("schema_type") or "string"), "json")


def _same_body(left: Exchange, right: Exchange) -> bool:
    if left.json_body is not None and right.json_body is not None:
        return left.json_body == right.json_body
    return left.body_text.strip() == right.body_text.strip()


class FailOpenCheck:
    name = "fail_open"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            required = [
                param
                for param in endpoint.parameters
                if param.get("in") == "query" and param.get("required") and "{" not in endpoint.path
            ]
            if not required:
                continue
            draft = await self._probe(ctx, endpoint, required)
            if draft is not None:
                findings.append(draft)
        return findings

    async def _send(self, ctx: ScanContext, path: str, params: dict[str, str]) -> Exchange:
        response = await ctx.client.send("GET", path, params=params or None)
        if response.status in {401, 403}:
            profile = next(iter(user_profiles(ctx)), None)
            if profile is not None:
                response = await ctx.client.send("GET", path, params=params or None, profile=profile)
        return response

    async def _probe(
        self, ctx: ScanContext, endpoint: EndpointSpec, required: list[dict]
    ) -> FindingDraft | None:
        base = {param["name"]: _placeholder(param) for param in required}
        control = await self._send(ctx, endpoint.path, base)
        if control.status >= 400:
            return None
        potential: FindingDraft | None = None
        for param in required:
            name = param["name"]
            omitted = {key: value for key, value in base.items() if key != name}
            response = await self._send(ctx, endpoint.path, omitted)
            if response.status >= 400:
                continue
            same = _same_body(control, response)
            draft = FindingDraft(
                category="fail_open",
                severity="medium" if same else "low",
                status="confirmed" if same else "potential",
                title=f"Required parameter {name} can be omitted",
                description=(
                    f"{endpoint.label} documents {name} as required. Omitting it still returns success"
                    + (
                        ", and the body matches the request that included the parameter."
                        if same
                        else ", but the body differs from the request that included the parameter."
                    )
                ),
                owasp_id="A10:2025",
                owasp_web="A10:2025",
                remediation=REMEDIATION,
                endpoint_key=endpoint.label,
                evidence={
                    "subtype": "fail_open",
                    "parameter": name,
                    "notes": "The omitted call is compared with one placeholder value. A 4xx is ignored.",
                    "requests": [
                        excerpt(control, f"{name} present"),
                        excerpt(response, f"{name} omitted"),
                    ],
                },
            )
            if same:
                return draft
            potential = potential or draft
        return potential
