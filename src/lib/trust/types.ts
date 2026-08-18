export type SignalCategory =
  | "infrastructure"
  | "domain"
  | "identity"
  | "reputation"
  | "content"
  | "anomaly";

/**
 * Four fundamentally different results — plus `info` for neutral facts.
 * `unknown` means NOVAIN could not observe the signal. It is NEVER scored,
 * neither positively nor negatively.
 */
export type SignalResult = "pass" | "warning" | "fail" | "unknown" | "info";

export type Severity = "none" | "low" | "medium" | "high" | "critical";

/**
 * Standardized evidence record emitted by every source adapter.
 * Every score contribution in the engine MUST map to one of these.
 */
export interface Evidence {
  evidence_id: string;
  /** Adapter that produced this record. */
  source_id: string;
  /** Human-readable provenance (never invented). */
  source: string;
  category: SignalCategory;
  /** What was checked. */
  signal: string;
  /** Raw observation, as observed. */
  observation: string;
  result: SignalResult;
  severity: Severity;
  /** 0..1 — how much we trust this observation. */
  confidence: number;
  /** Score delta applied to the category (points). Ignored when result = unknown. */
  weight: number;
  /** Why this observation matters for the risk assessment. */
  explanation: string;
  timestamp: string;
}

export type SourceStatus = "ok" | "unavailable" | "error";

export interface SourceReport {
  source_id: string;
  label: string;
  status: SourceStatus;
  detail: string;
  duration_ms: number;
  evidence_count: number;
}

export type RiskLevel = "very_low" | "low" | "medium" | "high" | "critical";
export type VerificationStatus =
  | "VERIFIED"
  | "UNVERIFIED"
  | "WARNING"
  | "HIGH_RISK"
  | "CRITICAL";

export type CategoryState = "known" | "partial" | "unknown";

export interface CategoryResult {
  category: SignalCategory;
  /** null when nothing observable was collected — explicitly UNKNOWN, not 0. */
  score: number | null;
  state: CategoryState;
  result: SignalResult;
  /** Nominal model weight. */
  weight: number;
  /** Weight actually applied after unknown categories are removed (0..1). */
  effective_weight: number;
  confidence: number;
  known_signals: number;
  unknown_signals: number;
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
  /** Share of the model's nominal weight that could actually be observed (0..1). */
  coverage: number;
  capped: boolean;
  applied_gates: RiskGate[];
  categories: Record<SignalCategory, CategoryResult>;
  checks: Record<SignalCategory, SignalResult>;
  sources: SourceReport[];
  evidence: Evidence[];
  recommendation: string;
  duration_ms: number;
  checked_at: string;
  model_version: string;
}
