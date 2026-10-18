"""Request and response schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuthProfileIn(BaseModel):
    name: str
    role: str = "user"
    type: Literal["bearer", "api_key", "basic", "none"] = "bearer"
    token: str | None = None
    subject: str | None = None
    api_key_header: str = "X-API-Key"
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    login_path: str | None = None

    def to_storage(self) -> dict[str, Any]:
        data = self.model_dump()
        data["auth_type"] = data.pop("type")
        return data


class ManualEndpointIn(BaseModel):
    method: str
    path: str
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    auth_required: bool = True
    tags: list[str] = Field(default_factory=list)
    security: dict[str, Any] | None = None


class ScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_base_url: str
    scope_confirmed: bool
    discovery_mode: Literal["openapi", "manual"]
    spec_document: dict[str, Any] | None = None
    spec_text: str | None = None
    openapi_url: str | None = None
    manual_endpoints: list[ManualEndpointIn] = Field(default_factory=list)
    profiles: list[AuthProfileIn] = Field(default_factory=list)
    checks: list[str] = Field(
        default_factory=lambda: [
            "bola",
            "auth_jwt",
            "data_exposure",
            "resource_limits",
            "bfla",
            "ssrf",
            "misconfig",
            "inventory",
            "unsafe_consumption",
            "injection",
            "fail_open",
        ]
    )
    concurrency: int = 4
    rate_limit_rps: float = 5
    collaborator_base_url: str | None = None
    id_probes: list[int] = Field(default_factory=lambda: [101, 102, 1, 2])


class EndpointRead(BaseModel):
    id: str
    method: str
    path: str
    auth_required: bool
    security: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class FindingRead(BaseModel):
    id: str
    category: str
    severity: str
    status: str
    title: str
    description: str
    owasp_id: str
    owasp_web: str | None = None
    endpoint_label: str | None
    remediation: str
    evidence: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: str
    name: str
    target_base_url: str
    discovery_mode: str
    status: str
    error_message: str | None
    scope_confirmed: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    findings_count: int
    confirmed_count: int


class ScanDetail(ScanSummary):
    findings: list[FindingRead]
    endpoints: list[EndpointRead]
    warnings: list[str] = Field(default_factory=list)
