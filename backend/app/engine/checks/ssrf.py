"""SSRF detection via a caller-configured collaborator. No metadata probes."""

from uuid import uuid4

import httpx

from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, ScanContext

URL_NAMES = {
    "url",
    "uri",
    "link",
    "webhook",
    "callback",
    "dest",
    "redirect",
    "website",
    "fetch_url",
    "endpoint_url",
    "target_url",
}
REMEDIATION = (
    "Do not request arbitrary URLs supplied by the client. If a fetch is required, allowlist the hosts "
    "and block metadata, link-local, and unexpected internal addresses."
)


class SsrfCheck:
    name = "ssrf"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        if not ctx.collaborator_base_url:
            return []
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            for name in self._url_params(endpoint):
                draft = await self._probe(ctx, endpoint, name)
                if draft:
                    findings.append(draft)
        return findings

    def _url_params(self, endpoint: EndpointSpec) -> list[str]:
        names = []
        for param in endpoint.parameters:
            if param.get("in") == "query" and str(param.get("name", "")).lower() in URL_NAMES:
                names.append(param["name"])
        return names

    async def _probe(self, ctx: ScanContext, endpoint: EndpointSpec, name: str) -> FindingDraft | None:
        token = uuid4().hex
        marker = f"ARGUS-CALLBACK-{token}"
        callback = f"{ctx.collaborator_base_url.rstrip('/')}/marker/{token}"
        response = await ctx.client.send("GET", endpoint.path, params={name: callback})
        if response.status in {401, 403} and ctx.profiles:
            profile = next((item for item in ctx.profiles if item.token or item.auth_type != "bearer"), None)
            response = await ctx.client.send("GET", endpoint.path, params={name: callback}, profile=profile)
        hit = marker in response.body_text
        if not hit:
            hit = await self._poll(ctx.collaborator_base_url, token)
        if not hit:
            return None
        return FindingDraft(
            category="ssrf",
            severity="high",
            status="confirmed",
            title="SSRF confirmed through the callback",
            description=(
                f"Parameter {name} on {endpoint.label} makes the server send an HTTP request "
                "to the supplied URL. The lab callback received the call."
            ),
            owasp_id="API7:2023", owasp_web="A01:2025",
            remediation=REMEDIATION,
            endpoint_key=endpoint.label,
            evidence={
                "notes": "The payload is only the configured collaborator URL. Metadata hosts are not probed.",
                "requests": [excerpt(response, f"parameter {name}")],
            },
        )

    async def _poll(self, base_url: str, token: str) -> bool:
        url = f"{base_url.rstrip('/')}/hits/{token}"
        try:
            async with httpx.AsyncClient(timeout=4, follow_redirects=False) as client:
                response = await client.get(url)
        except httpx.HTTPError:
            return False
        if response.status_code >= 400:
            return False
        try:
            payload = response.json()
        except Exception:
            return False
        return int(payload.get("count") or 0) > 0
