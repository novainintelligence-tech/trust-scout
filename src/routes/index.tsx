import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { EvidenceList } from "@/components/trust/EvidenceList";
import type { VerificationReport } from "@/lib/trust/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NOVAIN TRUST — Evidence-Driven Website Risk Verification" },
      {
        name: "description",
        content:
          "NOVAIN TRUST verifies websites with an evidence-driven risk engine: infrastructure, domain, identity, reputation, content and anomaly signals, each with source and confidence.",
      },
      { property: "og:title", content: "NOVAIN TRUST — Evidence-Driven Website Verification" },
      {
        property: "og:description",
        content:
          "Every score contribution maps to stored evidence. Unavailable data sources are marked unavailable, never scored as positive.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const statusStyle: Record<string, string> = {
  VERIFIED: "text-verified border-verified/50 bg-verified/10",
  UNVERIFIED: "text-unverified border-border bg-muted/40",
  WARNING: "text-warning border-warning/50 bg-warning/10",
  HIGH_RISK: "text-highrisk border-highrisk/50 bg-highrisk/10",
  CRITICAL: "text-critical border-critical/50 bg-critical/10",
};

const SAMPLES = ["wikipedia.org", "stripe.com", "example.com"];

function Index() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<(VerificationReport & { persisted?: boolean }) | null>(null);

  async function run(target: string) {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/public/v1/verify/website", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.message ?? json.error ?? "Verification failed");
      setReport(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-background px-4 py-10 sm:px-8">
      <div className="mx-auto w-full max-w-3xl">
        <header>
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-primary">Novain Trust</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Evidence-driven website risk verification
          </h1>
          <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
            Every point in the score maps to a stored observation with a source, timestamp and
            confidence. HTTPS and a 200 response are treated as baseline facts — never as proof of
            trust. Where an external source is unavailable, the signal is marked unavailable rather
            than scored positively.
          </p>
        </header>

        <form
          className="mt-8 flex flex-col gap-3 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            run(url);
          }}
        >
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            aria-label="Website to verify"
            className="flex-1 rounded-md border border-input bg-surface px-4 py-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground focus:ring-2 focus:ring-ring"
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-md bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Collecting evidence…" : "Verify"}
          </button>
        </form>

        <div className="mt-3 flex flex-wrap gap-2">
          {SAMPLES.map((s) => (
            <button
              key={s}
              onClick={() => {
                setUrl(s);
                run(s);
              }}
              className="rounded-full border border-border px-3 py-1 font-mono text-xs text-muted-foreground hover:border-primary hover:text-primary"
            >
              {s}
            </button>
          ))}
        </div>

        {error && (
          <p className="mt-6 rounded-md border border-critical/50 bg-critical/10 p-4 text-sm text-critical">
            {error}
          </p>
        )}

        {report && (
          <section className="mt-10 space-y-8">
            <div className="rounded-lg border border-border bg-card p-6">
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`rounded border px-3 py-1 font-mono text-xs font-semibold tracking-wide ${statusStyle[report.status]}`}
                >
                  {report.status.replace("_", " ")}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  risk: {report.risk_level.replace("_", " ")}
                </span>
                <span className="ml-auto text-right">
                  <span className="text-3xl font-semibold text-foreground">
                    {report.trust_score}
                  </span>
                  <span className="text-sm text-muted-foreground">/100</span>
                </span>
              </div>
              <p className="mt-4 text-sm text-foreground">{report.recommendation}</p>
              <dl className="mt-4 grid grid-cols-2 gap-3 font-mono text-[11px] text-muted-foreground sm:grid-cols-4">
                <div>
                  <dt>raw score</dt>
                  <dd className="text-foreground">{report.raw_score}</dd>
                </div>
                <div>
                  <dt>confidence</dt>
                  <dd className="text-foreground">{report.confidence}</dd>
                </div>
                <div>
                  <dt>duration</dt>
                  <dd className="text-foreground">{report.duration_ms}ms</dd>
                </div>
                <div>
                  <dt>stored</dt>
                  <dd className="text-foreground">{report.persisted ? "yes" : "no"}</dd>
                </div>
              </dl>
              <p className="mt-4 break-all font-mono text-[11px] text-muted-foreground">
                verificationId: {report.verification_id} · {report.checked_at} ·{" "}
                {report.model_version}
              </p>
            </div>

            {report.applied_gates.length > 0 && (
              <div className="rounded-lg border border-warning/40 bg-warning/5 p-5">
                <h2 className="text-sm font-semibold text-warning">
                  Risk gates applied (score capped)
                </h2>
                <ul className="mt-3 space-y-2 text-xs text-foreground">
                  {report.applied_gates.map((g) => (
                    <li key={g.gate}>
                      <span className="font-mono text-warning">{g.gate}</span> — caps score at{" "}
                      {g.cap}. {g.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <h2 className="text-sm font-semibold text-foreground">Signal categories</h2>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                {Object.values(report.categories).map((c) => (
                  <div key={c.category} className="rounded-md border border-border bg-card p-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm capitalize text-foreground">{c.category}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {c.score === null ? "unavailable" : `${c.score}/100`} · w{c.weight}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                      outcome: {c.outcome} · confidence {c.confidence} · {c.evidence_ids.length}{" "}
                      evidence items
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-foreground">
                Evidence ({report.evidence.length} items)
              </h2>
              <div className="mt-3">
                <EvidenceList evidence={report.evidence} />
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
