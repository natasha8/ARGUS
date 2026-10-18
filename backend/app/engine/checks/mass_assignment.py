"""Mass assignment, the write side of OWASP API3:2023.

This check is opt-in. It is not part of the default set, because it sends a
state-changing request. It is deliberately conservative:

- it only targets PATCH or PUT endpoints that have a matching GET on the same
  path, so it can read the object before and after;
- it only flips a privileged property that is already present in the GET
  response (role-like strings or boolean flags), never an invented field;
- it restores the original value immediately after the probe and records
  whether the restore succeeded.
"""

from app.engine.checks.base import concrete_paths, path_param_names, user_profiles
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, ScanContext

REMEDIATION = (
    "Bind only the properties a client is allowed to change. Use an explicit input schema "
    "for writes and never copy the whole request body onto the stored object. Privileged "
    "fields such as role or verification flags must be set server-side."
)

ROLE_KEYS = {"role", "account_type", "accounttype", "user_type", "usertype"}
FLAG_KEYS = {"is_admin", "isadmin", "admin", "is_staff", "isstaff", "verified", "email_verified", "superuser"}
WRITE_METHODS = {"PATCH", "PUT"}


def _read_field(data, key: str):
    if isinstance(data, dict):
        if key in data:
            return data[key], True
        for value in data.values():
            found, ok = _read_field(value, key)
            if ok:
                return found, True
    return None, False


def _privileged_value(key: str, current):
    if isinstance(current, bool):
        return True if current is False else None
    if isinstance(current, str) and key.lower() in ROLE_KEYS:
        return "admin" if current.lower() != "admin" else None
    return None


class MassAssignmentCheck:
    name = "mass_assignment"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        profile = next(
            (item for item in user_profiles(ctx) if item.auth_type != "bearer" or item.token),
            None,
        )
        if profile is None:
            return []
        gets = {
            endpoint.path: endpoint
            for endpoint in ctx.endpoints
            if endpoint.method == "GET"
        }
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method not in WRITE_METHODS:
                continue
            get_endpoint = gets.get(endpoint.path)
            if get_endpoint is None:
                continue
            draft = await self._probe(ctx, endpoint, get_endpoint, profile)
            if draft is not None:
                findings.append(draft)
        return findings

    async def _probe(
        self,
        ctx: ScanContext,
        endpoint: EndpointSpec,
        get_endpoint: EndpointSpec,
        profile,
    ) -> FindingDraft | None:
        names = path_param_names(endpoint.path)
        read_path = concrete_paths(get_endpoint, ctx.id_probes)[0] if names else get_endpoint.path
        write_path = concrete_paths(endpoint, ctx.id_probes)[0] if names else endpoint.path
        baseline = await ctx.client.send("GET", read_path, profile=profile)
        if baseline.status >= 400 or baseline.json_body is None:
            return None
        for key in list(ROLE_KEYS) + list(FLAG_KEYS):
            current, present = _read_field(baseline.json_body, key)
            if not present:
                continue
            injected = _privileged_value(key, current)
            if injected is None:
                continue
            write = await ctx.client.send(endpoint.method, write_path, profile=profile, json_body={key: injected})
            if write.status >= 400:
                continue
            after = await ctx.client.send("GET", read_path, profile=profile)
            after_value, _ = _read_field(after.json_body, key)
            changed = after_value == injected and after_value != current
            # Always try to restore, regardless of the outcome.
            restore = await ctx.client.send(endpoint.method, write_path, profile=profile, json_body={key: current})
            restored_value, _ = _read_field(
                (await ctx.client.send("GET", read_path, profile=profile)).json_body, key
            )
            if not changed:
                continue
            restore_note = (
                "The original value was restored after the probe."
                if restored_value == current
                else f"Warning: could not restore {key}; current value may still be the probe value."
            )
            return FindingDraft(
                category="mass_assignment",
                severity="high",
                status="confirmed",
                title=f"Mass assignment of {key} on {endpoint.label}",
                description=(
                    f"Sending {key} in the body of {endpoint.label} as profile {profile.name} changed the stored "
                    f"value, confirmed by re-reading {get_endpoint.label}. The client can set a property it should not control."
                ),
                owasp_id="API3:2023",
                remediation=REMEDIATION,
                endpoint_key=endpoint.label,
                evidence={
                    "subtype": "mass_assignment",
                    "property": key,
                    "notes": f"The property {key} was flipped and then restored. {restore_note}",
                    "requests": [
                        excerpt(baseline, "before"),
                        excerpt(write, f"write {key}"),
                        excerpt(after, "after"),
                        excerpt(restore, "restore"),
                    ],
                },
            )
        return None
