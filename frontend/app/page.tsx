"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { listScans, type ScanSummary } from "../lib/api";

const STATUS: Record<string, string> = {
  pending: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

export default function HomePage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const data = await listScans();
        if (!stop) {
          setScans(data);
          setError("");
        }
      } catch (err) {
        if (!stop) setError(err instanceof Error ? err.message : "API unreachable");
      }
    };
    tick();
    const timer = setInterval(tick, 3000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <main>
      <div className="row">
        <div>
          <h1>Scans</h1>
          <p className="lede">History of checks against APIs you are authorized to test.</p>
        </div>
        <Link className="button" href="/scans/new">
          New scan
        </Link>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Target</th>
              <th>Status</th>
              <th>Finding</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No scans yet. The local lab is described in the guide.
                </td>
              </tr>
            )}
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>
                  <Link href={`/scans/${scan.id}`}>{scan.name}</Link>
                  <div className="muted mono">{new Date(scan.created_at).toLocaleString("en-US")}</div>
                </td>
                <td className="mono">{scan.target_base_url}</td>
                <td>
                  <span className={`pill ${scan.status}`}>{STATUS[scan.status] || scan.status}</span>
                </td>
                <td>
                  {scan.findings_count} <span className="muted">({scan.confirmed_count} confirmed)</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
