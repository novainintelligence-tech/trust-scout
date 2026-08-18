import type { Evidence, SourceReport } from "../types";
import type { SourceAdapter, SourceContext } from "./base";
import { rdapSource } from "./rdap";
import { dnsSource } from "./dns";
import { tlsSource } from "./tls";
import { httpSource } from "./http";
import { contentSource } from "./content";
import { identitySource } from "./identity";
import { reputationSource, historySource } from "./reputation";
import { anomalySource } from "./anomaly";

export type { SourceAdapter, SourceContext } from "./base";

/** Sources that can run independently and in parallel. */
export const PRIMARY_SOURCES: SourceAdapter[] = [
  httpSource,
  rdapSource,
  dnsSource,
  tlsSource,
  contentSource,
  identitySource,
  reputationSource,
  historySource,
];

/** Sources that correlate the output of the primary sources. */
export const CORRELATION_SOURCES: SourceAdapter[] = [anomalySource];

async function runAdapter(
  adapter: SourceAdapter,
  ctx: SourceContext,
  collected: Evidence[],
): Promise<{ report: SourceReport; evidence: Evidence[] }> {
  const started = Date.now();
  try {
    const out = await adapter.run(ctx, collected);
    return {
      report: {
        source_id: adapter.id,
        label: adapter.label,
        status: out.status,
        detail: out.detail,
        duration_ms: Date.now() - started,
        evidence_count: out.evidence.length,
      },
      evidence: out.evidence,
    };
  } catch (err) {
    return {
      report: {
        source_id: adapter.id,
        label: adapter.label,
        status: "error",
        detail: err instanceof Error ? err.message : String(err),
        duration_ms: Date.now() - started,
        evidence_count: 0,
      },
      evidence: [],
    };
  }
}

/** Source orchestrator: fan out to every adapter, then run correlation adapters. */
export async function orchestrate(
  ctx: SourceContext,
): Promise<{ evidence: Evidence[]; sources: SourceReport[] }> {
  const primary = await Promise.all(PRIMARY_SOURCES.map((a) => runAdapter(a, ctx, [])));
  const evidence = primary.flatMap((p) => p.evidence);
  const sources = primary.map((p) => p.report);

  const correlated = await Promise.all(
    CORRELATION_SOURCES.map((a) => runAdapter(a, ctx, evidence)),
  );
  for (const c of correlated) {
    evidence.push(...c.evidence);
    sources.push(c.report);
  }

  return { evidence, sources };
}
