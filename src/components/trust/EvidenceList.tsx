import type { Evidence } from "@/lib/trust/types";

const resultStyle: Record<string, string> = {
  pass: "text-verified border-verified/40 bg-verified/10",
  info: "text-muted-foreground border-border bg-muted/40",
  warning: "text-warning border-warning/40 bg-warning/10",
  fail: "text-critical border-critical/40 bg-critical/10",
  unknown: "text-unverified border-border bg-muted/30",
};

const resultLabel: Record<string, string> = {
  pass: "PASS",
  fail: "FAIL",
  warning: "WARNING",
  unknown: "UNKNOWN",
  info: "INFO",
};

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  return (
    <ul className="space-y-3">
      {evidence.map((item) => (
        <li key={item.evidence_id} className="rounded-md border border-border bg-card p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wide ${resultStyle[item.result]}`}
            >
              {resultLabel[item.result] ?? item.result}
            </span>
            <span className="text-sm font-medium text-foreground">{item.signal}</span>
            <span className="ml-auto font-mono text-[11px] text-muted-foreground">
              {item.category} · {item.source_id} · conf {item.confidence.toFixed(2)} ·{" "}
              {item.result === "unknown"
                ? "not scored"
                : `${item.weight > 0 ? "+" : ""}${item.weight} pts`}
            </span>
          </div>
          <p className="mt-2 font-mono text-xs text-foreground/90">{item.observation}</p>
          <p className="mt-2 text-xs text-muted-foreground">{item.explanation}</p>
          <p className="mt-2 text-[11px] text-muted-foreground">
            Source: {item.source} · Observed: {item.timestamp}
          </p>
        </li>
      ))}
    </ul>
  );
}
