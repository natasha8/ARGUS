"""Rate-limited HTTP client used by every check."""

import asyncio
import base64
import time
from typing import Any

import httpx

from app.engine.types import Exchange, Profile

USER_AGENT = "Argus-API-Scanner/1.0 (authorized-testing)"


def auth_headers(profile: Profile | None) -> dict[str, str]:
    if profile is None or profile.auth_type in {"none", ""}:
        return {}
    if profile.auth_type == "bearer" and profile.token:
        return {"Authorization": f"Bearer {profile.token}"}
    if profile.auth_type == "api_key" and profile.api_key:
        return {profile.api_key_header or "X-API-Key": profile.api_key}
    if profile.auth_type == "basic" and profile.username is not None:
        raw = f"{profile.username}:{profile.password or ''}".encode()
        encoded = base64.b64encode(raw).decode()
        return {"Authorization": f"Basic {encoded}"}
    return {}


def excerpt(exchange: Exchange, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "method": exchange.method,
        "url": exchange.url,
        "status": exchange.status,
        "elapsed_ms": exchange.elapsed_ms,
        "body_excerpt": exchange.body_text[:1200],
        "error": exchange.error,
    }


class ProbeClient:
    def __init__(
        self,
        base_url: str,
        rate_limit_rps: float = 5,
        concurrency: int = 4,
        timeout: float = 8.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)
        self._gap = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0
        self._lock = asyncio.Lock()
        self._next = 0.0
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    def resolve(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    async def send(
        self,
        method: str,
        path: str,
        *,
        profile: Profile | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Exchange:
        async with self._sem:
            await self._pace()
            return await self._do(method, path, profile=profile, params=params, json_body=json_body, headers=headers)

    async def _pace(self) -> None:
        if self._gap <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + self._gap
        if wait > 0:
            await asyncio.sleep(wait)

    async def _do(
        self,
        method: str,
        path: str,
        *,
        profile: Profile | None,
        params: dict[str, Any] | None,
        json_body: Any,
        headers: dict[str, str] | None,
    ) -> Exchange:
        url = self.resolve(path)
        merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        merged.update(auth_headers(profile))
        if headers:
            merged.update(headers)
        started = time.perf_counter()
        try:
            response = await self._client.request(
                method.upper(),
                url,
                params=params,
                json=json_body,
                headers=merged,
            )
        except httpx.HTTPError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return Exchange(method.upper(), url, 0, "", None, elapsed, error=str(exc))
        elapsed = int((time.perf_counter() - started) * 1000)
        text = response.text[:8000]
        parsed: Any = None
        content_type = response.headers.get("content-type", "")
        if "json" in content_type or text.startswith("{") or text.startswith("["):
            try:
                parsed = response.json()
            except Exception:
                parsed = None
        headers = {key.lower(): value for key, value in response.headers.items()}
        return Exchange(
            method.upper(), str(response.url), response.status_code, text, parsed, elapsed, headers=headers
        )
