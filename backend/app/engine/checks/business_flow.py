"""Unrestricted access to sensitive business flows (OWASP API6:2023).

Opt-in. Sends two identical POST requests, with the same Idempotency-Key, to
paths that look like checkout, payment, or a similar flow. Confirmed only when
a readable counter increases by one on the second call.
"""

from uuid import uuid4

from app.engine.checks.base import json_list_len
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, Exchange, FindingDraft, ScanContext

FLOW_HINTS = ("checkout", "purchase", "transfer", "payment", "redeem", "invite")
REMEDIATION = (
    "Require an idempotency key, and reject or replay the original result when the same "
    "business operation is submitted twice."
)


def _count(exchange: Exchange) -> int | None:
    data = exchange.json_body
    if isinstance(data, dict):
        value = data.get("count")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return json_list_len(exchange)


class BusinessFlowCheck:
    name = "business_flow"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "POST" or not self._matches(endpoint):
                continue
            draft = await self._probe(ctx, endpoint)
            if draft:
                findings.append(draft)
        return findings

    def _matches(self, endpoint: EndpointSpec) -> bool:
        blob = " ".join([endpoint.path, *endpoint.tags]).lower()
        return any(hint in blob for hint in FLOW_HINTS)

    def _body(self, endpoint: EndpointSpec) -> dict:
        properties = ((endpoint.request_body or {}).get("properties") or [])
        body = {}
        for prop in properties:
            name = prop.get("name")
            if name:
                body[str(name)] = "notebook"
        return body or {"sku": "notebook"}

    async def _probe(self, ctx: ScanContext, endpoint: EndpointSpec) -> FindingDraft | None:
        key = uuid4().hex
        headers = {"Idempotency-Key": key}
        body = self._body(endpoint)
        first = await ctx.client.send(endpoint.method, endpoint.path, json_body=body, headers=headers)
        if first.status >= 400:
            return None
        second = await ctx.client.send(endpoint.method, endpoint.path, json_body=body, headers=headers)
        if second.status >= 400:
            return None
        before = _count(first)
        after = _count(second)
        if before is not None and after == before + 1:
            status = "confirmed"
            severity = "medium"
            notes = "Both calls succeeded and the counter increased, so the idempotency key was ignored."
        elif before is None or after is None:
            status = "potential"
            severity = "low"
            notes = "Both calls succeeded, but the response has no count to show that a second object was created."
        else:
            return None
        return FindingDraft(
            category="business_flow",
            severity=severity,
            status=status,
            title="Sensitive flow accepts the same request twice",
            description=(
                f"{endpoint.label} accepted two identical requests that carried the same Idempotency-Key."
            ),
            owasp_id="API6:2023", owasp_web="A06:2025",
            remediation=REMEDIATION,
            endpoint_key=endpoint.label,
            evidence={
                "notes": notes,
                "requests": [excerpt(first, "first"), excerpt(second, "second")],
            },
        )
