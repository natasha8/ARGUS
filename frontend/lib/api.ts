export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Finding = {
  id: string;
  category: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  owasp_id: string;
  owasp_web?: string | null;
  endpoint_label: string | null;
  remediation: string;
  evidence: {
    notes?: string;
    affected_endpoints?: string[];
    requests?: {
      label: string;
      method: string;
      url: string;
      status: number;
      elapsed_ms: number;
      body_excerpt: string;
      error?: string | null;
    }[];
  };
};

export type ScanSummary = {
  id: string;
  name: string;
  target_base_url: string;
  discovery_mode: string;
  status: string;
  error_message: string | null;
  created_at: string;
  finished_at: string | null;
  findings_count: number;
  confirmed_count: number;
};

export type ScanDetail = ScanSummary & {
  findings: Finding[];
  endpoints: {
    id: string;
    method: string;
    path: string;
    auth_required: boolean;
    security?: { schemes?: { name: string; scheme?: string | null; type?: string | null }[] } | null;
  }[];
  warnings: string[];
};

export type Meta = {
  disclaimer: string;
  allowed_target_hosts: string[];
  checks: { id: string; title: string; owasp: string; summary: string }[];
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      detail = await response.text();
    }
    throw new Error(detail || "Request failed");
  }
  if (response.headers.get("content-type")?.includes("text/markdown")) {
    return (await response.text()) as T;
  }
  return response.json();
}

export const getMeta = () => request<Meta>("/meta");
export const listScans = () => request<ScanSummary[]>("/scans");
export const getScan = (id: string) => request<ScanDetail>(`/scans/${id}`);
export const createScan = (body: unknown) =>
  request<ScanSummary>("/scans", { method: "POST", body: JSON.stringify(body) });
export const getReport = (id: string, format: "markdown" | "json") =>
  request<string>(`/scans/${id}/report?format=${format}`);
