"use client";

import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { getReport, getScan, type Finding, type ScanDetail } from "../../../lib/api";

const STATUS: Record<string, string> = {
  pending: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  confirmed: "Confirmed",
  potential: "Potential",
};

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [category, setCategory] = useState("all");
  const [report, setReport] = useState("");

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const data = await getScan(scanId);
        if (stop) return;
        setScan(data);
        setError("");
        if (data.status === "pending" || data.status === "running") {
          setTimeout(tick, 2000);
        }
      } catch (err) {
        if (!stop) setError(err instanceof Error ? err.message : "Error");
      }
    };
    tick();
    return () => {
      stop = true;
    };
  }, [scanId]);

  const findings = useMemo(() => {
    return (scan?.findings || []).filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false;
      if (status !== "all" && finding.status !== status) return false;
      if (category !== "all" && finding.category !== category) return false;
      return true;
    });
  }, [scan, severity, status, category]);

  async function showReport(format: "markdown" | "json") {
    const text = await getReport(scanId, format);
    setReport(typeof text === "string" ? text : JSON.stringify(text, null, 2));
  }

  if (error) return <p className="error">{error}</p>;
  if (!scan) return <p className="muted">Loading...</p>;

  return (
    <main>
      <div className="row">
        <div>
          <h1>{scan.name}</h1>
          <p className="lede mono">{scan.target_base_url}</p>
        </div>
        <span className={`pill ${scan.status}`}>{STATUS[scan.status] || scan.status}</span>
      </div>
      {scan.error_message && <p className="error">{scan.error_message}</p>}
      {scan.warnings.length > 0 && <p className="muted">{scan.warnings.join(" ")}</p>}
      <p>
        {scan.findings_count} findings, {scan.confirmed_count} confirmed, {scan.endpoints.length} endpoints.
        A potential finding needs a manual review. An empty list does not prove the API is secure.
      </p>
      <div className="actions">
        <button className="button secondary" type="button" onClick={() => showReport("markdown")}>
          Report Markdown
        </button>
        <button className="button secondary" type="button" onClick={() => showReport("json")}>
          Report JSON
        </button>
      </div>
      {report && <pre>{report}</pre>}
      <div className="filters">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <select value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="all">All statuses</option>
          <option value="confirmed">confirmed</option>
          <option value="potential">potential</option>
        </select>
        <select value={category} onChange={(event) => setCategory(event.target.value)}>
          <option value="all">All categories</option>
          <option value="bola">BOLA</option>
          <option value="auth_jwt">JWT</option>
          <option value="data_exposure">Data exposure</option>
          <option value="resource_limits">Resource limits</option>
          <option value="bfla">BFLA</option>
          <option value="business_flow">Business flow</option>
          <option value="ssrf">SSRF</option>
          <option value="injection">Injection</option>
          <option value="fail_open">Fail-open</option>
          <option value="misconfig">Misconfiguration</option>
          <option value="inventory">Inventory</option>
          <option value="unsafe_consumption">Unsafe consumption</option>
          <option value="mass_assignment">Mass assignment</option>
        </select>
      </div>
      <div className="cards">
        {findings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
        {findings.length === 0 && <p className="muted">No findings match these filters.</p>}
      </div>
      <details>
        <summary>Discovered endpoints</summary>
        <div className="table-wrap" style={{ marginTop: 10 }}>
          <table>
            <tbody>
              {scan.endpoints.map((endpoint) => (
                <tr key={endpoint.id}>
                  <td className="mono">
                    {endpoint.method} {endpoint.path}
                  </td>
                  <td>{endpointLabel(endpoint)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </main>
  );
}

function endpointLabel(endpoint: ScanDetail["endpoints"][number]) {
  const schemes = (endpoint.security?.schemes || [])
    .map((scheme) => (scheme.scheme ? `${scheme.name} (${scheme.scheme})` : scheme.name))
    .filter(Boolean);
  const access = endpoint.auth_required ? "auth" : "public";
  return schemes.length ? `${access} · ${schemes.join(", ")}` : access;
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="card">
      <div className="row">
        <strong>{finding.title}</strong>
        <span>
          <span className={`pill ${finding.severity}`}>{finding.severity}</span>{" "}
          <span className={`pill ${finding.status}`}>{STATUS[finding.status] || finding.status}</span>
        </span>
      </div>
      <div className="muted">
        {finding.owasp_id}
        {finding.owasp_web && finding.owasp_web !== finding.owasp_id ? ` · ${finding.owasp_web}` : ""}
        {finding.endpoint_label ? ` · ${finding.endpoint_label}` : ""}
      </div>
      <p>{finding.description}</p>
      <p>
        <strong>Remediation. </strong>
        {finding.remediation}
      </p>
      {finding.evidence?.notes && <p className="muted">{finding.evidence.notes}</p>}
      {finding.evidence?.affected_endpoints && (
        <ul>
          {finding.evidence.affected_endpoints.map((item) => (
            <li key={item} className="mono">
              {item}
            </li>
          ))}
        </ul>
      )}
      {(finding.evidence?.requests || []).map((request) => (
        <details key={`${request.label}-${request.url}`}>
          <summary>
            {request.label}: {request.method} → {request.status}
          </summary>
          <pre>{request.body_excerpt || request.error || "empty body"}</pre>
        </details>
      ))}
    </article>
  );
}
