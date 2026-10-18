"""Security misconfiguration (OWASP API8:2023).

Three non-destructive signals:

- CORS: send an Origin header and see whether the server reflects it (and allows
  credentials), which lets any site read authenticated responses.
- Missing security headers: aggregate the common response headers that are absent.
- Verbose errors: a benign request to a random path that returns a stack trace or
  a debug page leaks internals.

Everything here is read-only. No state is changed.
"""

from uuid import uuid4

from app.engine.checks.base import concrete_paths
from app.engine.http import excerpt
from app.engine.types import FindingDraft, ScanContext

PROBE_ORIGIN = "https://argus-probe.example"
MAX_ENDPOINTS = 60

SECURITY_HEADERS = {
    "x-content-type-options": "Prevents MIME sniffing (expected: nosniff).",
    "x-frame-options": "Blocks clickjacking via framing (or use CSP frame-ancestors).",
    "content-security-policy": "Limits what the page can load.",
}
HTTPS_HEADERS = {
    "strict-transport-security": "Forces HTTPS on later visits.",
}

ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "werkzeug",
    "django.core",
    "sqlalchemy",
    "java.lang.",
    "at org.springframework",
    "system.web",
    "stack trace:",
    "<title>internal server error</title>",
    "debug = true",
)

REMEDIATION_CORS = (
    "Do not reflect arbitrary Origins. Allowlist the exact origins you trust, and never combine "
    "a reflected or wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true."
)
REMEDIATION_HEADERS = (
    "Set the standard security response headers at the edge or in middleware so every response carries them."
)
REMEDIATION_ERRORS = (
    "Return generic error messages to clients, disable debug mode in production, and log the detail server-side."
)


class MisconfigCheck:
    name = "misconfig"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        sample = self._sample_paths(ctx)
        if not sample:
            return findings
        cors = await self._cors(ctx, sample)
        if cors:
            findings.append(cors)
        headers = await self._headers(ctx, sample[0])
        if headers:
            findings.append(headers)
        errors = await self._verbose_errors(ctx)
        if errors:
            findings.append(errors)
        return findings

    def _sample_paths(self, ctx: ScanContext) -> list[tuple[str, str]]:
        seen: list[tuple[str, str]] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET":
                continue
            paths = concrete_paths(endpoint, ctx.id_probes)
            if paths:
                seen.append((endpoint.label, paths[0]))
            if len(seen) >= MAX_ENDPOINTS:
                break
        return seen

    async def _cors(self, ctx: ScanContext, sample: list[tuple[str, str]]) -> FindingDraft | None:
        reflected: list[str] = []
        with_credentials: list[str] = []
        evidence = []
        for label, path in sample:
            response = await ctx.client.send("GET", path, headers={"Origin": PROBE_ORIGIN})
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == PROBE_ORIGIN or acao == "*":
                reflected.append(label)
                if acac:
                    with_credentials.append(label)
                if len(evidence) < 3:
                    evidence.append(excerpt(response, f"Origin reflected on {label}"))
        if not reflected:
            return None
        if with_credentials:
            return FindingDraft(
                category="misconfig",
                severity="high",
                status="confirmed",
                title="CORS reflects the request origin with credentials",
                description=(
                    "The server echoes an attacker-supplied Origin in Access-Control-Allow-Origin and allows "
                    "credentials. Any site can read authenticated responses on behalf of a logged-in user."
                ),
                owasp_id="API8:2023",
                remediation=REMEDIATION_CORS,
                evidence={
                    "subtype": "cors",
                    "affected_endpoints": with_credentials,
                    "notes": "Confirmed: the probe Origin is reflected and credentials are allowed.",
                    "requests": evidence,
                },
            )
        return FindingDraft(
            category="misconfig",
            severity="medium",
            status="potential",
            title="CORS reflects the request origin or uses a wildcard",
            description=(
                "The server reflects the request Origin or returns a wildcard Access-Control-Allow-Origin. "
                "Without credentials the impact is lower, but it still relaxes the same-origin policy."
            ),
            owasp_id="API8:2023",
            remediation=REMEDIATION_CORS,
            evidence={
                "subtype": "cors",
                "affected_endpoints": reflected,
                "notes": "Reflected origin or wildcard without credentials. Review whether this is intended.",
                "requests": evidence,
            },
        )

    async def _headers(self, ctx: ScanContext, sample: tuple[str, str]) -> FindingDraft | None:
        label, path = sample
        response = await ctx.client.send("GET", path)
        if response.status >= 400 or response.error:
            return None
        expected = dict(SECURITY_HEADERS)
        if ctx.base_url.lower().startswith("https://"):
            expected.update(HTTPS_HEADERS)
        missing = [name for name in expected if name not in response.headers]
        if not missing:
            return None
        return FindingDraft(
            category="misconfig",
            severity="low",
            status="potential",
            title="Common security response headers are missing",
            description=(
                f"The response from {label} does not set: {', '.join(missing)}. These headers harden clients "
                "against sniffing, framing, and injection."
            ),
            owasp_id="API8:2023",
            remediation=REMEDIATION_HEADERS,
            evidence={
                "subtype": "headers",
                "missing_headers": [{"name": name, "purpose": expected[name]} for name in missing],
                "notes": "Header presence is a baseline; confirm the right policy for your API by hand.",
                "requests": [excerpt(response, f"headers on {label}")],
            },
        )

    async def _verbose_errors(self, ctx: ScanContext) -> FindingDraft | None:
        probe_path = f"/argus-probe-{uuid4().hex[:8]}"
        response = await ctx.client.send("GET", probe_path)
        body = response.body_text.lower()
        signature = next((sig for sig in ERROR_SIGNATURES if sig in body), None)
        is_server_error = response.status >= 500
        if signature is None and not is_server_error:
            return None
        if signature is not None:
            return FindingDraft(
                category="misconfig",
                severity="medium",
                status="confirmed",
                title="Verbose error leaks internal details",
                description=(
                    "A request to a non-existent path returned a stack trace or debug page. "
                    "Error output exposes framework internals and file paths."
                ),
                owasp_id="API8:2023",
                remediation=REMEDIATION_ERRORS,
                evidence={
                    "subtype": "verbose_error",
                    "notes": f"Matched the signature '{signature}'.",
                    "requests": [excerpt(response, "unknown path")],
                },
            )
        return FindingDraft(
            category="misconfig",
            severity="low",
            status="potential",
            title="Server error on an unknown path",
            description=(
                "A request to a non-existent path returned a 5xx instead of a clean 404. "
                "Check that error handling does not leak details."
            ),
            owasp_id="API8:2023",
            remediation=REMEDIATION_ERRORS,
            evidence={
                "subtype": "verbose_error",
                "notes": "No stack-trace signature matched, but the status is 5xx.",
                "requests": [excerpt(response, "unknown path")],
            },
        )
