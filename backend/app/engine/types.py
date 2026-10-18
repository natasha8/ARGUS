"""Shared data structures for the scan engine."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Profile:
    name: str
    role: str = "user"
    auth_type: str = "bearer"
    token: str | None = None
    subject: str | None = None
    api_key_header: str = "X-API-Key"
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    login_path: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Profile":
        known = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: value for key, value in data.items() if key in known})


@dataclass
class EndpointSpec:
    method: str
    path: str
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)
    auth_required: bool = False
    security: dict[str, Any] = field(default_factory=lambda: {"requirements": [], "schemes": []})

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Exchange:
    method: str
    url: str
    status: int
    body_text: str
    json_body: Any
    elapsed_ms: int
    error: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class FindingDraft:
    category: str
    severity: str
    status: str
    title: str
    description: str
    owasp_id: str
    owasp_web: str
    remediation: str
    evidence: dict[str, Any]
    endpoint_key: str | None = None


@dataclass
class ScanContext:
    scan_id: str
    base_url: str
    endpoints: list[EndpointSpec]
    profiles: list[Profile]
    client: Any
    collaborator_base_url: str
    id_probes: list[int]
