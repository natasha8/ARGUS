import "./globals.css";
import Link from "next/link";
import type { ReactNode } from "react";

export const metadata = {
  title: "Argus",
  description: "Security scanner for authorized REST APIs",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="top">
            <div>
              <Link href="/" className="mark">
                <i />
                ARGUS
              </Link>
              <p className="disclaimer">
                Use it only on APIs you are explicitly authorized to test. Docker ports are bound to
                localhost.
              </p>
            </div>
            <nav className="nav">
              <Link href="/">Scans</Link>
              <Link href="/scans/new">New scan</Link>
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
