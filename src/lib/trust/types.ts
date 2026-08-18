export type SignalCategory =
  | "infrastructure"
  | "domain"
  | "identity"
  | "reputation"
  | "content"
  | "anomaly";

export type SignalOutcome = "pass" | "warning" | "fail" | "unavailable" | "info";

export type Severity = "none" | "low" | "medium" | "high" | "critical";

/**
 * A single piece of evidence. Every score contribution in the engine MUST come
 * from one of these records, so the final score is fully explainable.
 */
export interface Evidence {
  id: string;
  category: SignalCategory;
  /** What was checked. */
  check: string;
  /** Where the evidence came from (never invented). */
  source: string;
  /** Raw observation, as observed. */
  observation: string;
  outcome: SignalOutcome;
  severity: Severity;
  /** 0..1 — how much we trust this observation. */
  confidence: number;
  /** Score delta applied to the category (points, -100..+100). */
  weight: number;
  /** Why this observation matters for the risk assessment. */
  explanation: string;
  observed_at: string;
}

export type RiskLevel = "very_low" | "low" | "medium" | "high" | "critical";
export type VerificationStatus =
  | "VERIFIED"
  | "UNVERIFIED"
  | "WARNING"
  | "HIGH_RISK"
  | "CRITICAL";

export interface CategoryResult {
  category: SignalCategory;
  score: number | null;
  outcome: SignalOutcome;
  weight: number;
  confidence: number;
  evidence_ids: string[];
}

export interface RiskGate {
  gate: string;
  cap: number;
  reason: string;
  evidence_ids: string[];
}

export interface VerificationReport {
  verification_id: string;
  target: string;
  domain: string;
  status: VerificationStatus;
  risk_level: RiskLevel;
  trust_score: number;
  raw_score: number;
  confidence: number;
  capped: boolean;
  applied_gates: RiskGate[];
  categories: Record<SignalCategory, CategoryResult>;
  checks: Record<SignalCategory, SignalOutcome>;
  evidence: Evidence[];
  recommendation: string;
  duration_ms: number;
  checked_at: string;
  model_version: string;
}
