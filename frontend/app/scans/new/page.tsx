"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { createScan, getMeta, type Meta } from "../../../lib/api";

const ALL_CHECKS = [
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
];
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

type Profile = {
  name: string;
  role: string;
  type: "bearer" | "api_key" | "basic" | "none";
  username: string;
  password: string;
  login_path: string;
  token: string;
  api_key: string;
  api_key_header: string;
};

type ManualParam = {
  name: string;
  in: "path" | "query" | "header";
  schema_type: string;
  required: boolean;
};

type ManualEndpoint = {
  method: string;
  path: string;
  auth_required: boolean;
  tags: string;
  parameters: ManualParam[];
  body_properties: string;
  scheme_kind: "" | "bearer" | "apiKey" | "basic";
  scheme_name: string;
  scheme_param: string;
};

const emptyProfile = (): Profile => ({
  name: "user",
  role: "user",
  type: "bearer",
  username: "",
  password: "",
  login_path: "/api/login",
  token: "",
  api_key: "",
  api_key_header: "X-API-Key",
});

const emptyEndpoint = (): ManualEndpoint => ({
  method: "GET",
  path: "/api/orders/{order_id}",
  auth_required: true,
  tags: "",
  parameters: [{ name: "order_id", in: "path", schema_type: "string", required: true }],
  body_properties: "",
  scheme_kind: "",
  scheme_name: "",
  scheme_param: "X-API-Key",
});

const labProfiles = (): Profile[] => [
  { ...emptyProfile(), name: "alice", username: "alice", password: "alice123" },
  { ...emptyProfile(), name: "bob", username: "bob", password: "bob123" },
  { ...emptyProfile(), name: "admin", role: "admin", username: "admin", password: "admin123" },
];

export default function NewScanPage() {
  const router = useRouter();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("Lab scan");
  const [target, setTarget] = useState("http://127.0.0.1:8001");
  const [openapiUrl, setOpenapiUrl] = useState("http://127.0.0.1:8001/openapi.json");
  const [collaborator, setCollaborator] = useState("http://127.0.0.1:8090");
  const [mode, setMode] = useState<"openapi" | "manual">("openapi");
  const [specText, setSpecText] = useState<string | null>(null);
  const [specName, setSpecName] = useState("");
  const [endpoints, setEndpoints] = useState<ManualEndpoint[]>([emptyEndpoint()]);
  const [scope, setScope] = useState(false);
  const [checks, setChecks] = useState<string[]>(ALL_CHECKS);
  const [concurrency, setConcurrency] = useState(4);
  const [rateLimit, setRateLimit] = useState(8);
  const [profiles, setProfiles] = useState<Profile[]>([
    { ...emptyProfile(), name: "alice", username: "alice", password: "alice123" },
    { ...emptyProfile(), name: "bob", username: "bob", password: "bob123" },
  ]);

  useEffect(() => {
    getMeta().then(setMeta).catch(() => setMeta(null));
  }, []);

  function fillLocalLab() {
    setMode("openapi");
    setName("Local lab");
    setTarget("http://127.0.0.1:8001");
    setOpenapiUrl("http://127.0.0.1:8001/openapi.json");
    setCollaborator("http://127.0.0.1:8090");
    setSpecText(null);
    setSpecName("");
    setScope(true);
    setChecks(ALL_CHECKS);
    setConcurrency(4);
    setRateLimit(8);
    setProfiles(labProfiles());
  }

  function fillDockerLab() {
    fillLocalLab();
    setName("Docker lab");
    setTarget("http://vulnerable-api:8000");
    setOpenapiUrl("http://vulnerable-api:8000/openapi.json");
    setCollaborator("http://collaborator:8090");
  }

  function toggleCheck(id: string) {
    setChecks((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));
  }

  function updateProfile(index: number, patch: Partial<Profile>) {
    setProfiles((current) => current.map((profile, item) => (item === index ? { ...profile, ...patch } : profile)));
  }

  function updateEndpoint(index: number, patch: Partial<ManualEndpoint>) {
    setEndpoints((current) => current.map((endpoint, item) => (item === index ? { ...endpoint, ...patch } : endpoint)));
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 20) {
      setError("Concurrency must be a whole number from 1 to 20.");
      setBusy(false);
      return;
    }
    if (!Number.isFinite(rateLimit) || rateLimit < 0.2 || rateLimit > 50) {
      setError("Rate limit must be between 0.2 and 50 requests per second.");
      setBusy(false);
      return;
    }
    if (mode === "manual" && endpoints.some((endpoint) => !endpoint.path.trim().startsWith("/"))) {
      setError("Each manual path must start with /.");
      setBusy(false);
      return;
    }
    try {
      const created = await createScan({
        name,
        target_base_url: target,
        scope_confirmed: scope,
        discovery_mode: mode,
        openapi_url: mode === "openapi" && !specText ? openapiUrl : null,
        spec_document: null,
        spec_text: mode === "openapi" ? specText : null,
        manual_endpoints: mode === "manual" ? endpoints.map(toManualPayload) : [],
        profiles: profiles.map((profile) => ({
          name: profile.name,
          role: profile.role,
          type: profile.type,
          username: profile.username || null,
          password: profile.password || null,
          login_path: profile.type === "bearer" ? profile.login_path || null : null,
          token: profile.type === "bearer" ? profile.token || null : null,
          api_key: profile.type === "api_key" ? profile.api_key || null : null,
          api_key_header: profile.api_key_header || "X-API-Key",
        })),
        checks,
        concurrency,
        rate_limit_rps: rateLimit,
        collaborator_base_url: collaborator,
        id_probes: [101, 102, 1, 2],
      });
      router.push(`/scans/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Submit failed");
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>New scan</h1>
      <p className="lede">
        Import an OpenAPI or Swagger file, or describe endpoints yourself. Authorization tests need the profiles
        those endpoints expect: Bearer, API key, or Basic.
      </p>
      {meta && (
        <p className="muted">
          Allowed hosts: {meta.allowed_target_hosts.join(", ")}. {meta.disclaimer}
        </p>
      )}
      <div className="actions" style={{ margin: "16px 0" }}>
        <button className="button secondary" type="button" onClick={fillLocalLab}>
          Fill local lab
        </button>
        <button className="button secondary" type="button" onClick={fillDockerLab}>
          Fill Docker lab
        </button>
      </div>
      <form className="panel form" style={{ padding: 18 }} onSubmit={onSubmit}>
        <div className="split">
          <label>
            Name
            <input value={name} onChange={(event) => setName(event.target.value)} required />
          </label>
          <label>
            Target URL
            <input value={target} onChange={(event) => setTarget(event.target.value)} required />
          </label>
        </div>
        <div className="split">
          <label>
            Concurrency
            <input
              type="number"
              min={1}
              max={20}
              step={1}
              value={concurrency}
              onChange={(event) => setConcurrency(Number(event.target.value))}
              required
            />
          </label>
          <label>
            Requests per second
            <input
              type="number"
              min={0.2}
              max={50}
              step={0.1}
              value={rateLimit}
              onChange={(event) => setRateLimit(Number(event.target.value))}
              required
            />
          </label>
        </div>
        <p className="hint">Concurrency is 1–20. The rate limit is 0.2–50 requests per second.</p>
        <label>
          Discovery
          <select value={mode} onChange={(event) => setMode(event.target.value as "openapi" | "manual")}>
            <option value="openapi">OpenAPI / Swagger</option>
            <option value="manual">Manual endpoints</option>
          </select>
        </label>
        {mode === "openapi" ? (
          <div className="split">
            <label>
              URL OpenAPI
              <input
                value={openapiUrl}
                onChange={(event) => setOpenapiUrl(event.target.value)}
                required={!specText}
                disabled={Boolean(specText)}
              />
            </label>
            <label>
              Or upload JSON or YAML
              <input
                type="file"
                accept="application/json,.json,.yaml,.yml,text/yaml"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  setSpecText(await file.text());
                  setSpecName(file.name);
                }}
              />
            </label>
          </div>
        ) : (
          <ManualEditor
            endpoints={endpoints}
            onChange={updateEndpoint}
            onAdd={() => setEndpoints((current) => [...current, { ...emptyEndpoint(), path: "/", parameters: [] }])}
            onRemove={(index) => setEndpoints((current) => current.filter((_, item) => item !== index))}
          />
        )}
        {specName && mode === "openapi" && (
          <div className="subhead">
            <p className="hint">Using uploaded file {specName}. The URL is ignored until you clear it.</p>
            <button
              className="button secondary"
              type="button"
              onClick={() => {
                setSpecText(null);
                setSpecName("");
              }}
            >
              Clear file
            </button>
          </div>
        )}
        <label>
          Callback SSRF
          <input value={collaborator} onChange={(event) => setCollaborator(event.target.value)} />
        </label>
        <div>
          <div className="muted">Checks</div>
          <div className="checks" style={{ marginTop: 8 }}>
            {(meta?.checks || ALL_CHECKS.map((id) => ({ id, title: id, owasp: "", summary: "" }))).map((item) => (
              <label className="check" key={item.id}>
                <input type="checkbox" checked={checks.includes(item.id)} onChange={() => toggleCheck(item.id)} />
                {item.title}
              </label>
            ))}
          </div>
        </div>
        <div className="subhead">
          <h2 style={{ margin: 0 }}>Profiles</h2>
          <button className="button secondary" type="button" onClick={() => setProfiles((current) => [...current, emptyProfile()])}>
            Add profile
          </button>
        </div>
        {profiles.map((profile, index) => (
          <ProfileEditor
            key={`${index}-${profile.type}`}
            profile={profile}
            onChange={(patch) => updateProfile(index, patch)}
            onRemove={() => setProfiles((current) => current.filter((_, item) => item !== index))}
          />
        ))}
        {profiles.length === 0 && <p className="hint">No profiles. Authorization checks will have nothing to compare.</p>}
        <label className="check" style={{ width: "fit-content" }}>
          <input type="checkbox" checked={scope} onChange={(event) => setScope(event.target.checked)} />
          I confirm I am authorized to test this target
        </label>
        {error && <p className="error">{error}</p>}
        <button className="button" type="submit" disabled={busy}>
          {busy ? "Starting..." : "Start scan"}
        </button>
      </form>
    </main>
  );
}

function ProfileEditor({
  profile,
  onChange,
  onRemove,
}: {
  profile: Profile;
  onChange: (patch: Partial<Profile>) => void;
  onRemove: () => void;
}) {
  return (
    <div className="editor">
      <div className="subhead">
        <strong>{profile.name || "Profile"}</strong>
        <button className="button secondary" type="button" onClick={onRemove}>
          Remove
        </button>
      </div>
      <div className="split-3">
        <label>
          Name
          <input value={profile.name} onChange={(event) => onChange({ name: event.target.value })} required />
        </label>
        <label>
          Role
          <input value={profile.role} onChange={(event) => onChange({ role: event.target.value })} />
        </label>
        <label>
          Type
          <select value={profile.type} onChange={(event) => onChange({ type: event.target.value as Profile["type"] })}>
            <option value="bearer">Bearer / JWT</option>
            <option value="api_key">API key</option>
            <option value="basic">Basic</option>
            <option value="none">None</option>
          </select>
        </label>
      </div>
      {profile.type === "bearer" && (
        <>
          <label>
            Token
            <input
              value={profile.token}
              onChange={(event) => onChange({ token: event.target.value })}
              placeholder="Leave empty to log in"
            />
          </label>
          <div className="split-3">
            <label>
              Username
              <input value={profile.username} onChange={(event) => onChange({ username: event.target.value })} />
            </label>
            <label>
              Password
              <input
                type="password"
                value={profile.password}
                onChange={(event) => onChange({ password: event.target.value })}
              />
            </label>
            <label>
              Login path
              <input value={profile.login_path} onChange={(event) => onChange({ login_path: event.target.value })} />
            </label>
          </div>
          <p className="hint">If the token is empty, Argus POSTs the username and password to the login path.</p>
        </>
      )}
      {profile.type === "api_key" && (
        <div className="split">
          <label>
            API key
            <input value={profile.api_key} onChange={(event) => onChange({ api_key: event.target.value })} />
          </label>
          <label>
            Header name
            <input
              value={profile.api_key_header}
              onChange={(event) => onChange({ api_key_header: event.target.value })}
            />
          </label>
        </div>
      )}
      {profile.type === "basic" && (
        <div className="split">
          <label>
            Username
            <input value={profile.username} onChange={(event) => onChange({ username: event.target.value })} />
          </label>
          <label>
            Password
            <input
              type="password"
              value={profile.password}
              onChange={(event) => onChange({ password: event.target.value })}
            />
          </label>
        </div>
      )}
    </div>
  );
}

function ManualEditor({
  endpoints,
  onChange,
  onAdd,
  onRemove,
}: {
  endpoints: ManualEndpoint[];
  onChange: (index: number, patch: Partial<ManualEndpoint>) => void;
  onAdd: () => void;
  onRemove: (index: number) => void;
}) {
  return (
    <div className="stack">
      <div className="subhead">
        <h2 style={{ margin: 0 }}>Endpoints</h2>
        <button className="button secondary" type="button" onClick={onAdd}>
          Add endpoint
        </button>
      </div>
      {endpoints.map((endpoint, index) => (
        <div className="editor" key={index}>
          <div className="subhead">
            <strong>
              {endpoint.method} {endpoint.path || "/"}
            </strong>
            <button className="button secondary" type="button" onClick={() => onRemove(index)} disabled={endpoints.length === 1}>
              Remove
            </button>
          </div>
          <div className="split">
            <label>
              Method
              <select value={endpoint.method} onChange={(event) => onChange(index, { method: event.target.value })}>
                {METHODS.map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Path
              <input value={endpoint.path} onChange={(event) => onChange(index, { path: event.target.value })} required />
            </label>
          </div>
          <div className="split">
            <label>
              Tags
              <input
                value={endpoint.tags}
                placeholder="admin, orders"
                onChange={(event) => onChange(index, { tags: event.target.value })}
              />
            </label>
            <label>
              JSON body fields
              <input
                value={endpoint.body_properties}
                placeholder="name, q"
                onChange={(event) => onChange(index, { body_properties: event.target.value })}
              />
            </label>
          </div>
          <label className="check" style={{ width: "fit-content" }}>
            <input
              type="checkbox"
              checked={endpoint.auth_required}
              onChange={(event) => onChange(index, { auth_required: event.target.checked })}
            />
            Requires authentication
          </label>
          {endpoint.auth_required && (
            <div className="split-3">
              <label>
                Scheme
                <select
                  value={endpoint.scheme_kind}
                  onChange={(event) =>
                    onChange(index, { scheme_kind: event.target.value as ManualEndpoint["scheme_kind"] })
                  }
                >
                  <option value="">Unspecified</option>
                  <option value="bearer">Bearer</option>
                  <option value="apiKey">API key</option>
                  <option value="basic">Basic</option>
                </select>
              </label>
              <label>
                Scheme name
                <input
                  value={endpoint.scheme_name}
                  placeholder="HTTPBearer"
                  onChange={(event) => onChange(index, { scheme_name: event.target.value })}
                />
              </label>
              <label>
                Header
                <input
                  value={endpoint.scheme_param}
                  disabled={endpoint.scheme_kind !== "apiKey"}
                  onChange={(event) => onChange(index, { scheme_param: event.target.value })}
                />
              </label>
            </div>
          )}
          <div className="subhead">
            <span className="muted">Parameters</span>
            <button
              className="button secondary"
              type="button"
              onClick={() =>
                onChange(index, {
                  parameters: [...endpoint.parameters, { name: "", in: "query", schema_type: "string", required: false }],
                })
              }
            >
              Add parameter
            </button>
          </div>
          {endpoint.parameters.map((param, paramIndex) => (
            <div className="split-3" key={paramIndex}>
              <label>
                Name
                <input
                  value={param.name}
                  onChange={(event) => {
                    const parameters = endpoint.parameters.map((item, cursor) =>
                      cursor === paramIndex ? { ...item, name: event.target.value } : item
                    );
                    onChange(index, { parameters });
                  }}
                />
              </label>
              <label>
                In
                <select
                  value={param.in}
                  onChange={(event) => {
                    const parameters = endpoint.parameters.map((item, cursor) =>
                      cursor === paramIndex ? { ...item, in: event.target.value as ManualParam["in"] } : item
                    );
                    onChange(index, { parameters });
                  }}
                >
                  <option value="path">path</option>
                  <option value="query">query</option>
                  <option value="header">header</option>
                </select>
              </label>
              <label>
                Type
                <input
                  value={param.schema_type}
                  onChange={(event) => {
                    const parameters = endpoint.parameters.map((item, cursor) =>
                      cursor === paramIndex ? { ...item, schema_type: event.target.value } : item
                    );
                    onChange(index, { parameters });
                  }}
                />
              </label>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function toManualPayload(endpoint: ManualEndpoint) {
  const properties = endpoint.body_properties
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((property) => ({ name: property, schema_type: "string" }));
  const scheme =
    endpoint.auth_required && endpoint.scheme_kind && endpoint.scheme_name.trim()
      ? endpoint.scheme_kind === "apiKey"
        ? {
            name: endpoint.scheme_name.trim(),
            type: "apiKey",
            scheme: null,
            location: "header",
            param_name: endpoint.scheme_param.trim() || "X-API-Key",
          }
        : {
            name: endpoint.scheme_name.trim(),
            type: "http",
            scheme: endpoint.scheme_kind,
            location: null,
            param_name: null,
          }
      : null;
  return {
    method: endpoint.method,
    path: endpoint.path.trim(),
    auth_required: endpoint.auth_required,
    tags: endpoint.tags
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    parameters: endpoint.parameters
      .filter((param) => param.name.trim())
      .map((param) => ({
        name: param.name.trim(),
        in: param.in,
        schema_type: param.schema_type || "string",
        required: param.required || param.in === "path",
      })),
    request_body: properties.length ? { content_type: "application/json", properties } : null,
    security: scheme
      ? { requirements: [[{ name: scheme.name, scopes: [] }]], schemes: [scheme] }
      : { requirements: [], schemes: [] },
  };
}
