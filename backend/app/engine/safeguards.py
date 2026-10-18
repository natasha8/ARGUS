"""Scope checks. Argus refuses targets outside the allowlist."""

from urllib.parse import urlparse

from app.config import settings
from app.disclaimer import ALLOWED_CHECKS

BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
}


class ScopeError(ValueError):
    """Raised when a scan is outside the authorized scope."""


def allowed_hosts() -> set[str]:
    return {item.strip().lower() for item in settings.allowed_target_hosts.split(",") if item.strip()}


def assert_url_allowed(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError("Only http and https URLs are allowed.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ScopeError("URL has no host.")
    if host in BLOCKED_HOSTS or host.startswith("169.254."):
        raise ScopeError("This host is blocked (metadata / link-local).")
    if host not in allowed_hosts():
        allowed = ", ".join(sorted(allowed_hosts()))
        raise ScopeError(f"Host '{host}' is not in the allowlist. Allowed hosts: {allowed}.")
    return url.strip()


def validate_scan_options(
    *,
    target_base_url: str,
    scope_confirmed: bool,
    checks: list[str],
    concurrency: int,
    rate_limit_rps: float,
    openapi_url: str | None,
) -> None:
    if not scope_confirmed:
        raise ScopeError("Confirm that you are authorized to test this target.")
    assert_url_allowed(target_base_url)
    if openapi_url:
        assert_url_allowed(openapi_url)
    unknown = [name for name in checks if name not in ALLOWED_CHECKS]
    if unknown:
        raise ScopeError(f"Unknown checks: {', '.join(unknown)}.")
    if not checks:
        raise ScopeError("Select at least one check.")
    if not 1 <= concurrency <= 20:
        raise ScopeError("Concurrency must be between 1 and 20.")
    if not 0.2 <= rate_limit_rps <= 50:
        raise ScopeError("Rate limit must be between 0.2 and 50 requests per second.")
