import type { Evidence, SignalCategory, SignalResult, Severity, SourceStatus } from "../types";
import type { FetchResult } from "../collectors";

export const UA = "NOVAIN-TRUST-Verifier/1.1 (+evidence-collection)";

let counter = 0;

export interface EvidenceInput {
  source: string;
  category: SignalCategory;
  signal: string;
  observation: string;
  result: SignalResult;
  severity?: Severity;
  confidence: number;
  weight?: number;
  explanation: string;
}

/** Builds a standardized evidence record. Unknown results can never carry weight. */
export function makeEvidence(sourceId: string, input: EvidenceInput): Evidence {
  counter += 1;
  const unknown = input.result === "unknown";
  return {
    evidence_id: `${sourceId}-${counter}`,
    source_id: sourceId,
    source: input.source,
    category: input.category,
    signal: input.signal,
    observation: input.observation,
    result: input.result,
    severity: unknown ? "none" : (input.severity ?? "none"),
    confidence: unknown ? 0 : input.confidence,
    weight: unknown ? 0 : (input.weight ?? 0),
    explanation: input.explanation,
    timestamp: new Date().toISOString(),
  };
}

export interface SourceContext {
  url: string;
  domain: string;
  hostname: string;
  https: FetchResult;
  plain: FetchResult;
  /** Lowercased visible text of the landing page. */
  body: string;
}

export interface SourceOutput {
  status: SourceStatus;
  detail: string;
  evidence: Evidence[];
}

export interface SourceAdapter {
  id: string;
  label: string;
  run(ctx: SourceContext, collected: Evidence[]): Promise<SourceOutput>;
}

export async function fetchJson<T = unknown>(
  url: string,
  { timeoutMs = 8000, accept = "application/json" }: { timeoutMs?: number; accept?: string } = {},
): Promise<{ ok: boolean; data: T | null; error: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept, "user-agent": UA },
    });
    if (!res.ok) return { ok: false, data: null, error: `HTTP ${res.status}` };
    return { ok: true, data: (await res.json()) as T, error: null };
  } catch (err) {
    return { ok: false, data: null, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchText(
  url: string,
  timeoutMs = 8000,
): Promise<{ ok: boolean; text: string; error: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { "user-agent": UA } });
    if (!res.ok) return { ok: false, text: "", error: `HTTP ${res.status}` };
    return { ok: true, text: await res.text(), error: null };
  } catch (err) {
    return { ok: false, text: "", error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

/* --------------------------------- DNS (DoH) -------------------------------- */

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}
export interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

export async function resolveDns(
  name: string,
  type: string,
  resolver = "https://dns.google/resolve",
): Promise<{ ok: boolean; data: DohResponse | null; error: string | null }> {
  const url = `${resolver}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  return fetchJson<DohResponse>(url, { timeoutMs: 7000, accept: "application/dns-json" });
}
