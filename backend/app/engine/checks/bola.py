"""BOLA / IDOR: another authenticated user reads an object they do not own."""

from app.engine.checks.base import (
    fill_path,
    find_ids,
    find_owner,
    parent_collection_path,
    path_param_names,
    user_profiles,
)
from app.engine.http import excerpt
from app.engine.types import EndpointSpec, FindingDraft, Profile, ScanContext

REMEDIATION = (
    "Authorize every read on the server by comparing the object owner "
    "with the token identity. Do not trust the id sent by the client."
)


class BolaCheck:
    name = "bola"

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        profiles = [profile for profile in user_profiles(ctx) if profile.token or profile.auth_type != "bearer"]
        profiles = [profile for profile in profiles if profile.auth_type != "bearer" or profile.token]
        if len(profiles) < 2:
            return []
        findings: list[FindingDraft] = []
        for endpoint in ctx.endpoints:
            if endpoint.method != "GET" or not endpoint.auth_required:
                continue
            if not path_param_names(endpoint.path):
                continue
            draft = await self._check_endpoint(ctx, endpoint, profiles)
            if draft:
                findings.append(draft)
        return findings

    async def _check_endpoint(
        self, ctx: ScanContext, endpoint: EndpointSpec, profiles: list[Profile]
    ) -> FindingDraft | None:
        ids = await self._candidate_ids(ctx, endpoint, profiles[0])
        subjects = {(profile.subject or profile.username or "").lower() for profile in profiles}
        potential: FindingDraft | None = None
        for object_id in ids:
            filled = fill_path(endpoint.path, {name: object_id for name in path_param_names(endpoint.path)})
            if not filled:
                continue
            anon = await ctx.client.send("GET", filled, profile=None)
            if anon.status not in {401, 403}:
                continue
            responses = []
            for profile in profiles:
                response = await ctx.client.send("GET", filled, profile=profile)
                responses.append((profile, response))
            for profile, response in responses:
                if response.status >= 400:
                    continue
                owner = find_owner(response.json_body)
                subject = (profile.subject or profile.username or "").lower()
                if owner and owner.lower() != subject and owner.lower() in subjects:
                    other = next(item for item in profiles if (item.subject or "").lower() == owner.lower())
                    return FindingDraft(
                        category="bola",
                        severity="high",
                        status="confirmed",
                        title="Broken object level authorization (BOLA)",
                        description=(
                            f"Profile {profile.name} reads {filled} and receives an object "
                            f"owned by {other.name}. The anonymous request is rejected, so the resource "
                            "is not public: the ownership check is missing."
                        ),
                        owasp_id="API1:2023",
                        remediation=REMEDIATION,
                        endpoint_key=endpoint.label,
                        evidence={
                            "notes": "Confirmed: the owner in the body matches another authenticated profile.",
                            "requests": [
                                excerpt(response, f"{profile.name} reads {other.name}'s object"),
                                excerpt(anon, "anonymous"),
                            ],
                        },
                    )
                if owner is None and response.status < 400:
                    same = [
                        other_response
                        for other_profile, other_response in responses
                        if other_profile.name != profile.name and other_response.status < 400
                    ]
                    if same and same[0].body_text == response.body_text:
                        potential = FindingDraft(
                            category="bola",
                            severity="medium",
                            status="potential",
                            title="Possible BOLA without an owner field",
                            description=(
                                f"Two authenticated profiles receive the same response from {filled}, "
                                "while the anonymous request is rejected. There is no owner field to confirm the object."
                            ),
                            owasp_id="API1:2023",
                            remediation=REMEDIATION,
                            endpoint_key=endpoint.label,
                            evidence={
                                "notes": "Potential: identical responses across users, with no owner identifier.",
                                "requests": [excerpt(response, profile.name), excerpt(anon, "anonymous")],
                            },
                        )
        return potential

    async def _candidate_ids(self, ctx: ScanContext, endpoint: EndpointSpec, profile: Profile) -> list[str]:
        found: list[str] = []
        parent = parent_collection_path(endpoint.path)
        if parent:
            listing = await ctx.client.send("GET", parent, profile=profile)
            found.extend(find_ids(listing.json_body))
        for probe in ctx.id_probes:
            found.append(str(probe))
        deduped: list[str] = []
        for item in found:
            if item not in deduped:
                deduped.append(item)
        return deduped[:8]
