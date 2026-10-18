"""Injection checks.

Probes stay on read-oriented endpoints. SQL probes are boolean/error comparisons.
There are no stacked queries, no file reads, and no command chaining.
"""

from app.engine.checks.base import allows_active_probe, json_list_len
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, Exchange, FindingDraft, ScanContext

SQL_MARKERS = (
    "syntax error",
    "unrecognized token",
    "sqlite",
    "operationalerror",
    "you have an error in your sql syntax",
    "sql syntax",
    "psycopg",
    "mysql",
    "odbc",
    "sqlalchemy.exc",
)
SHELL_MARKERS = ("syntax error", "unexpected token", "unmatched quote", "/bin/sh", "sh:")
COMMAND_NAMES = {"host", "hostname", "ip", "domain", "cmd", "command"}
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
SQL_TRUE = "x' OR '1'='1' --"
SQL_FALSE = "x' OR '1'='2' --"
REMEDIATION = {
    "sql": "Use parameterized queries. Do not concatenate user input into SQL.",
    "nosql": "Do not pass user JSON objects into a query interpreter. Accept only the expected types.",
    "command": "Do not interpolate input into a shell. Pass arguments as a list, with an allowlist of values.",
}


def is_time_delayed(baseline_ms: int, probe_ms: int) -> bool:
    return probe_ms >= 900 and probe_ms >= baseline_ms + 700


def _has_marker(text: str, markers: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


class InjectionCheck:
    name = "injection"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if not allows_active_probe(endpoint):
                continue
            findings.extend(await self._sql(ctx, endpoint))
            findings.extend(await self._nosql(ctx, endpoint))
            findings.extend(await self._command(ctx, endpoint))
        return findings

    def _query_params(self, endpoint: EndpointSpec) -> list[dict]:
        selected = []
        for param in endpoint.parameters:
            if param.get("in") != "query":
                continue
            name = str(param.get("name", "")).lower()
            if name in COMMAND_NAMES or name in URL_NAMES:
                continue
            selected.append(param)
        return selected

    async def _sql(self, ctx: ScanContext, endpoint: EndpointSpec) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        for param in self._query_params(endpoint):
            if param.get("schema_type") not in {"string", "integer", "number"}:
                continue
            name = param["name"]
            if param.get("schema_type") != "string":
                quote = await ctx.client.send(endpoint.method, endpoint.path, params={name: "1'"})
                if _has_marker(quote.body_text, SQL_MARKERS):
                    findings.append(self._draft(endpoint, name, "sql", "potential", "medium", quote, None, None))
                continue
            baseline = await ctx.client.send(endpoint.method, endpoint.path, params={name: "notebook"})
            quote = await ctx.client.send(endpoint.method, endpoint.path, params={name: "'"})
            true_probe = await ctx.client.send(endpoint.method, endpoint.path, params={name: SQL_TRUE})
            false_probe = await ctx.client.send(endpoint.method, endpoint.path, params={name: SQL_FALSE})
            error = _has_marker(quote.body_text, SQL_MARKERS)
            true_len = json_list_len(true_probe)
            false_len = json_list_len(false_probe)
            baseline_len = json_list_len(baseline)
            differed = (
                true_len is not None
                and false_len is not None
                and true_len > false_len
                and (error or (baseline_len is not None and true_len > baseline_len))
            )
            delayed = False
            if error and _has_marker(quote.body_text, ("you have an error in your sql syntax", "mysql")):
                sleep = await ctx.client.send(
                    endpoint.method, endpoint.path, params={name: "x' OR SLEEP(1) --"}
                )
                delayed = is_time_delayed(baseline.elapsed_ms, sleep.elapsed_ms)
            if differed or delayed:
                findings.append(
                    self._draft(endpoint, name, "sql", "confirmed", "high", quote, true_probe, false_probe)
                )
            elif error:
                findings.append(
                    self._draft(endpoint, name, "sql", "potential", "medium", quote, true_probe, false_probe)
                )
        return findings

    async def _nosql(self, ctx: ScanContext, endpoint: EndpointSpec) -> list[FindingDraft]:
        if endpoint.method != "POST":
            return []
        properties = ((endpoint.request_body or {}).get("properties") or [])
        findings: list[FindingDraft] = []
        for prop in properties:
            name = prop.get("name")
            if not name:
                continue
            baseline = await ctx.client.send(endpoint.method, endpoint.path, json_body={name: "notebook"})
            operator = await ctx.client.send(endpoint.method, endpoint.path, json_body={name: {"$gt": ""}})
            base_len = json_list_len(baseline)
            op_len = json_list_len(operator)
            auth_bypass = baseline.status in {401, 403} and operator.status < 300
            if (base_len is not None and op_len is not None and op_len > base_len) or auth_bypass:
                findings.append(
                    FindingDraft(
                        category="injection",
                        severity="high",
                        status="confirmed",
                        title=f"Operator injection in parameter {name}",
                        description=(
                            f"Sending an operator object instead of a string makes {endpoint.label} "
                            "change its result. The API is interpreting the JSON structure."
                        ),
                        owasp_id="A05:2025", owasp_web="A05:2025",
                        remediation=REMEDIATION["nosql"],
                        endpoint_key=endpoint.label,
                        evidence={
                            "subtype": "nosql",
                            "notes": "Confirmed by comparing a string value with a $gt operator.",
                            "requests": [
                                excerpt(baseline, "string"),
                                excerpt(operator, "operator"),
                            ],
                        },
                    )
                )
        return findings

    async def _command(self, ctx: ScanContext, endpoint: EndpointSpec) -> list[FindingDraft]:
        if endpoint.method != "GET":
            return []
        findings: list[FindingDraft] = []
        for param in endpoint.parameters:
            if param.get("in") != "query":
                continue
            if str(param.get("name", "")).lower() not in COMMAND_NAMES:
                continue
            name = param["name"]
            baseline = await ctx.client.send("GET", endpoint.path, params={name: "127.0.0.1"})
            if _has_marker(baseline.body_text, SHELL_MARKERS):
                continue
            probes = []
            for payload in ("'", '"'):
                probes.append(await ctx.client.send("GET", endpoint.path, params={name: payload}))
            hits = [probe for probe in probes if _has_marker(probe.body_text, SHELL_MARKERS)]
            if not hits:
                continue
            status = "confirmed" if len(hits) >= 2 else "potential"
            severity = "high" if status == "confirmed" else "medium"
            findings.append(
                FindingDraft(
                    category="injection",
                    severity=severity,
                    status=status,
                    title=f"Parameter {name} is interpreted as a command",
                    description=(
                        f"A quote in parameter {name} produces a shell-style error, "
                        "while a plain value does not. The check does not run extra commands: "
                        "it only compares how metacharacters are handled."
                    ),
                    owasp_id="A05:2025", owasp_web="A05:2025",
                    remediation=REMEDIATION["command"],
                    endpoint_key=endpoint.label,
                    evidence={
                        "subtype": "command",
                        "notes": "Probes are limited to quotes. No command chaining.",
                        "requests": [excerpt(baseline, "baseline"), excerpt(hits[0], "quote")],
                    },
                )
            )
        return findings

    def _draft(
        self,
        endpoint: EndpointSpec,
        name: str,
        subtype: str,
        status: str,
        severity: str,
        quote: Exchange,
        true_probe: Exchange | None,
        false_probe: Exchange | None,
    ) -> FindingDraft:
        requests = [excerpt(quote, "quote")]
        if true_probe:
            requests.append(excerpt(true_probe, "true condition"))
        if false_probe:
            requests.append(excerpt(false_probe, "false condition"))
        label = "Possible SQL injection" if status == "potential" else "SQL injection"
        return FindingDraft(
            category="injection",
            severity=severity,
            status=status,
            title=f"{label} in parameter {name}",
            description=(
                f"Parameter {name} on {endpoint.label} changes the query or produces a SQL error. "
                "The probes are boolean and error comparisons, with no stacked queries and no writes."
            ),
            owasp_id="A05:2025", owasp_web="A05:2025",
            remediation=REMEDIATION["sql"],
            endpoint_key=endpoint.label,
            evidence={"subtype": subtype, "notes": f"Result: {status}.", "requests": requests},
        )
