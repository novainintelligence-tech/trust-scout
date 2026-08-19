import { fetchSite } from "./collectors";
import { orchestrate } from "./sources";
import type {
  CategoryResult,
  CategoryState,
  Evidence,
  RiskGate,
  RiskLevel,
  SignalCategory,
  SignalResult,
  VerificationReport,
  VerificationStatus,
} from "./types";

export const MODEL_VERSION = "novain-risk-2.0";

const CATEGORY_WEIGHTS: Record<SignalCategory, number> = {
  identity: 25,
  domain: 20,
  reputation: 15,
  infrastructure: 18,
  content: 12,
  anomaly: 10,
};

const TOTAL_WEIGHT = Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0);

export function normalizeTarget(input: string): { url: string; domain: string } | null {
  let raw = input.trim();
  if (!raw) return null;
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  try {
    const u = new URL(raw);
    if (!u.hostname.includes(".")) return null;
    return { url: u.toString(), domain: u.hostname.toLowerCase().replace(/^www\./, "") };
  } catch {
    return null;
  }
}

function text(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();
}

/* ---------------------------------- scoring --------------------------------- */

/** Aggregate result of a category, computed over KNOWN signals only. */
function categoryResult(items: Evidence[]): SignalResult {
  const known = items.filter((i) => i.result !== "unknown");
  if (!known.length) return "unknown";
  if (known.some((i) => i.result === "fail")) return "fail";
  if (known.some((i) => i.result === "warning")) return "warning";
  if (known.some((i) => i.result === "pass")) return "pass";
  return "info";
}

function state(known: number, unknown: number): CategoryState {
  if (known === 0) return "unknown";
  return unknown > 0 ? "partial" : "known";
}

function scoreCategories(all: Evidence[]): Record<SignalCategory, CategoryResult> {
  const categories = Object.keys(CATEGORY_WEIGHTS) as SignalCategory[];
  const result = {} as Record<SignalCategory, CategoryResult>;

  // First pass: score each category from its known evidence only.
  for (const category of categories) {
    const items = all.filter((e) => e.category === category);
    const known = items.filter((e) => e.result !== "unknown");
    const unknown = items.length - known.length;
    const delta = known.reduce((sum, e) => sum + e.weight * e.confidence, 0);
    result[category] = {
      category,
      score: known.length ? Math.max(0, Math.min(100, Math.round(50 + delta))) : null,
      state: state(known.length, unknown),
      result: categoryResult(items),
      weight: CATEGORY_WEIGHTS[category],
      effective_weight: 0,
      confidence: known.length
        ? Number((known.reduce((s, e) => s + e.confidence, 0) / known.length).toFixed(2))
        : 0,
      known_signals: known.length,
      unknown_signals: unknown,
      evidence_ids: items.map((e) => e.evidence_id),
    };
  }

  // Second pass: renormalize weights across categories that were actually observed,
  // so an UNKNOWN source neither raises nor lowers the final score.
  const observedWeight =
    categories.reduce((s, c) => s + (result[c].score === null ? 0 : CATEGORY_WEIGHTS[c]), 0) || 1;
  for (const c of categories) {
    result[c].effective_weight =
      result[c].score === null ? 0 : Number((CATEGORY_WEIGHTS[c] / observedWeight).toFixed(3));
  }
  return result;
}

function applyGates(
  raw: number,
  all: Evidence[],
  categories: Record<SignalCategory, CategoryResult>,
): { score: number; gates: RiskGate[] } {
  const gates: RiskGate[] = [];

  const identity = categories.identity;
  const identityUnknown = identity.score === null;
  const identityWeak = !identityUnknown && (identity.result === "fail" || (identity.score ?? 0) < 50);
  if (identityUnknown || identityWeak) {
    gates.push({
      gate: identityUnknown ? "identity_unknown" : "identity_unresolved",
      cap: 69,
      reason: identityUnknown
        ? "Operator identity could not be observed at all (UNKNOWN). Trust must be positively established, so the score is capped at medium."
        : "Operator identity is not independently resolved, so the target cannot exceed a medium trust score regardless of other signals.",
      evidence_ids: identity.evidence_ids,
    });
  }

  const critical = all.filter((e) => e.severity === "critical" && e.result === "fail");
  if (critical.length) {
    gates.push({
      gate: "critical_security_indicator",
      cap: 15,
      reason: "A critical security indicator was observed.",
      evidence_ids: critical.map((e) => e.evidence_id),
    });
  }

  const high = all.filter((e) => e.severity === "high" && e.result === "fail");
  if (high.length) {
    gates.push({
      gate: "high_severity_indicator",
      cap: 35,
      reason: "One or more high-severity risk indicators were observed.",
      evidence_ids: high.map((e) => e.evidence_id),
    });
  }

  const unreachable = all.some(
    (e) => e.signal === "HTTPS reachability" && e.result === "fail",
  );
  if (unreachable) {
    gates.push({
      gate: "target_unreachable",
      cap: 40,
      reason: "The target could not be reached, so almost no evidence exists to support trust.",
      evidence_ids: all.filter((e) => e.signal === "HTTPS reachability").map((e) => e.evidence_id),
    });
  }

  const score = gates.reduce((acc, g) => Math.min(acc, g.cap), raw);
  return { score, gates };
}

function riskLevel(score: number): RiskLevel {
  if (score < 30) return "critical";
  if (score < 50) return "high";
  if (score < 70) return "medium";
  if (score < 85) return "low";
  return "very_low";
}

function statusFor(score: number, gates: RiskGate[], coverage: number): VerificationStatus {
  if (gates.some((g) => g.gate === "critical_security_indicator") || score < 20) return "CRITICAL";
  if (score < 40) return "HIGH_RISK";
  if (score < 60) return "WARNING";
  // Insufficient observed evidence can never yield VERIFIED, however high the score.
  if (score < 80 || coverage < 0.6) return "UNVERIFIED";
  return "VERIFIED";
}

function recommend(status: VerificationStatus, gates: RiskGate[]): string {
  const identity = gates.some((g) => g.gate.startsWith("identity"));
  switch (status) {
    case "CRITICAL":
      return "Do not transact. Critical risk indicators were observed in the collected evidence.";
    case "HIGH_RISK":
      return "Avoid payments or credential entry. Independent verification through another channel is required first.";
    case "WARNING":
      return "Proceed only with strong safeguards: verify the operator out-of-band and use reversible payment methods.";
    case "UNVERIFIED":
      return identity
        ? "No disqualifying signals found, but the operator's identity is unresolved or unknown. Confirm the legal entity before payment."
        : "No disqualifying signals found, but the evidence collected is insufficient to confirm trust.";
    case "VERIFIED":
    default:
      return "Evidence supports proceeding; still apply standard payment verification for high-value transactions.";
  }
}

/* ---------------------------------- engine ---------------------------------- */

export async function verifyWebsite(input: string): Promise<VerificationReport> {
  const started = Date.now();
  const normalized = normalizeTarget(input);
  if (!normalized) throw new Error("INVALID_TARGET");
  const { url, domain } = normalized;

  const [httpsRes, plainRes] = await Promise.all([
    fetchSite(url.startsWith("https://") ? url : `https://${domain}`),
    fetchSite(`http://${domain}`, 8000),
  ]);

  const { evidence, sources } = await orchestrate({
    url,
    domain,
    hostname: new URL(url).hostname.toLowerCase(),
    https: httpsRes,
    plain: plainRes,
    body: text(httpsRes.html),
  });

  const categories = scoreCategories(evidence);
  const scored = (Object.values(categories) as CategoryResult[]).filter((c) => c.score !== null);
  const raw = scored.length
    ? Math.round(scored.reduce((s, c) => s + (c.score as number) * c.effective_weight, 0))
    : 0;

  const { score, gates } = applyGates(raw, evidence, categories);

  const coverage = Number(
    (scored.reduce((s, c) => s + c.weight, 0) / TOTAL_WEIGHT).toFixed(2),
  );
  const known = evidence.filter((e) => e.result !== "unknown");
  const evidenceConfidence = known.length
    ? known.reduce((s, e) => s + e.confidence, 0) / known.length
    : 0;
  const confidence = Number((coverage * evidenceConfidence).toFixed(2));

  const checks = Object.fromEntries(
    (Object.values(categories) as CategoryResult[]).map((c) => [c.category, c.result]),
  ) as Record<SignalCategory, SignalResult>;

  const status = statusFor(score, gates, coverage);

  return {
    verification_id: crypto.randomUUID(),
    target: url,
    domain,
    status,
    risk_level: riskLevel(score),
    trust_score: score,
    raw_score: raw,
    confidence,
    coverage,
    capped: score < raw,
    applied_gates: gates,
    categories,
    checks,
    sources,
    evidence,
    recommendation: recommend(status, gates),
    duration_ms: Date.now() - started,
    checked_at: new Date().toISOString(),
    model_version: MODEL_VERSION,
  };
}
