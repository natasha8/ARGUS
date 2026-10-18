"""Resolve login flows and attach tokens to profiles."""

from app.engine.http import ProbeClient
from app.engine.jwtutil import peek_subject
from app.engine.types import Profile


async def resolve_profiles(client: ProbeClient, profiles: list[Profile]) -> tuple[list[Profile], list[str]]:
    warnings: list[str] = []
    for profile in profiles:
        if profile.auth_type == "bearer" and not profile.token and profile.login_path:
            body = {"username": profile.username, "password": profile.password}
            response = await client.send("POST", profile.login_path, json_body=body)
            data = response.json_body if isinstance(response.json_body, dict) else {}
            token = data.get("access_token") or data.get("token")
            if response.status >= 400 or not token:
                warnings.append(f"Login failed for profile {profile.name} (HTTP {response.status}).")
                continue
            profile.token = str(token)
            profile.subject = str(data.get("sub") or profile.username or "")
            if data.get("role"):
                profile.role = str(data["role"])
        if profile.auth_type == "bearer" and profile.token and not profile.subject:
            profile.subject = peek_subject(profile.token) or profile.username
        if profile.subject is None and profile.username:
            profile.subject = profile.username
    return profiles, warnings
