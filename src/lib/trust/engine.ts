import { evidence, fetchRdap, fetchSite, parseRdap, type FetchResult } from "./collectors";
import type {
  CategoryResult,
  Evidence,
  RiskGate,
  RiskLevel,
  SignalCategory,
  SignalOutcome,
  VerificationReport,
  VerificationStatus,
} from "./types";

export const MODEL_VERSION = "novain-risk-1.0";

const CATEGORY_WEIGHTS: Record<SignalCategory, number> = {
  identity: 25,
  domain: 20,
  reputation: 15,
  infrastructure: 18,
  content: 12,
  anomaly: 10,
};

const HIGH_RISK_TLDS = [
  "zip",
  "mov",
  "top",
  "xyz",
  "gq",
  "cf",
  "ml",
  "tk",
  "work",
  "click",
  "country",
  "loan",
  "rest",
  "quest",
];

const SUSPICIOUS_CONTENT = [
  "connect wallet",
  "seed phrase",
  "private key",
  "gift card",
  "wire transfer",
  "verify your account",
  "your account has been suspended",
  "claim your reward",
  "double your",
  "airdrop",
  "act now",
  "limited time only",
];

const IDENTITY_MARKERS = [
  "about us",
  "about",
  "contact",
  "imprint",
  "impressum",
  "legal",
  "terms",
  "privacy",
  "company",
  "registered office",
  "vat",
  "registration number",
];

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

/* ---------------------------------- signals --------------------------------- */

function infrastructureSignals(url: string, https: FetchResult, plain: FetchResult): Evidence[] {
  const out: Evidence[] = [];
  const isHttps = url.startsWith("https://");

  if (!https.ok) {
    out.push(
      evidence(
        "infrastructure",
        "HTTPS connection",
        "Direct TLS/HTTP request from NOVAIN infrastructure",
        `Request to ${url} failed: ${https.error}`,
        "fail",
        "high",
        0.9,
        -35,
        "The host could not be reached over HTTPS, so no live evidence about the service could be collected.",
      ),
    );
    return out;
  }

  out.push(
    evidence(
      "infrastructure",
      "TLS handshake and HTTPS reachability",
      "Direct TLS/HTTP request from NOVAIN infrastructure",
      `HTTPS request succeeded with status ${https.status} in ${https.elapsedMs}ms (final URL ${https.finalUrl})`,
      https.status && https.status < 400 ? "info" : "warning",
      "none",
      0.95,
      https.status && https.status < 400 ? 0 : -8,
      "A valid certificate and a successful response prove the service is online and encrypted. This is a baseline requirement, NOT evidence of trustworthiness — certificates are free and available to any actor.",
    ),
  );

  if (isHttps) {
    const hsts = https.headers["strict-transport-security"];
    out.push(
      evidence(
        "infrastructure",
        "HTTP Strict Transport Security",
        "Response headers",
        hsts ? `Strict-Transport-Security: ${hsts}` : "No Strict-Transport-Security header present",
        hsts ? "pass" : "warning",
        hsts ? "none" : "low",
        0.9,
        hsts ? 6 : -4,
        "HSTS shows deliberate transport hardening; its absence is a weak negative signal, not proof of malice.",
      ),
    );
  }

  const csp = https.headers["content-security-policy"];
  const xfo = https.headers["x-frame-options"];
  const xcto = https.headers["x-content-type-options"];
  const hardened = [csp, xfo, xcto].filter(Boolean).length;
  out.push(
    evidence(
      "infrastructure",
      "Security response headers",
      "Response headers",
      `Present: ${[csp && "content-security-policy", xfo && "x-frame-options", xcto && "x-content-type-options"].filter(Boolean).join(", ") || "none"}`,
      hardened >= 2 ? "pass" : hardened === 1 ? "warning" : "warning",
      hardened === 0 ? "low" : "none",
      0.85,
      hardened >= 2 ? 8 : hardened === 1 ? 2 : -6,
      "Security headers indicate an operator that invests in application hardening.",
    ),
  );

  if (plain.ok) {
    const upgraded = plain.finalUrl.startsWith("https://");
    out.push(
      evidence(
        "infrastructure",
        "Plain HTTP to HTTPS upgrade",
        "Direct HTTP request from NOVAIN infrastructure",
        `http://${new URL(url).hostname} resolved to ${plain.finalUrl}`,
        upgraded ? "pass" : "fail",
        upgraded ? "none" : "medium",
        0.9,
        upgraded ? 6 : -14,
        "Serving plaintext HTTP without redirecting exposes users to interception and credential theft.",
      ),
    );
  } else {
    out.push(
      evidence(
        "infrastructure",
        "Plain HTTP to HTTPS upgrade",
        "Direct HTTP request from NOVAIN infrastructure",
        `HTTP probe unavailable: ${plain.error}`,
        "unavailable",
        "none",
        0.3,
        0,
        "The plaintext probe could not be completed, so no conclusion is drawn in either direction.",
      ),
    );
  }

  return out;
}

async function domainSignals(domain: string): Promise<Evidence[]> {
  const out: Evidence[] = [];
  const labels = domain.split(".");
  const tld = labels[labels.length - 1] ?? "";

  const rdap = await fetchRdap(domain);
  const facts = rdap.ok ? parseRdap(rdap.data) : null;

  if (!facts) {
    out.push(
      evidence(
        "domain",
        "Domain registration record (RDAP)",
        "rdap.org (IANA RDAP bootstrap)",
        `Registration data unavailable: ${rdap.error ?? "no parsable record"}`,
        "unavailable",
        "none",
        0.2,
        0,
        "No registration evidence could be retrieved. Domain age and registrar remain UNKNOWN — this is explicitly not scored as positive.",
      ),
    );
  } else {
    const age = facts.ageDays;
    out.push(
      evidence(
        "domain",
        "Domain registration record (RDAP)",
        `${rdap.source} (IANA RDAP bootstrap)`,
        `Registered: yes; created ${facts.registrationDate ?? "unknown"}; registrar ${facts.registrar ?? "unknown"}; statuses ${facts.statuses.join(", ") || "none"}`,
        "pass",
        "none",
        0.9,
        4,
        "An authoritative registry record exists for this domain.",
      ),
    );
    if (age !== null) {
      const years = (age / 365).toFixed(1);
      const weight = age < 30 ? -30 : age < 180 ? -18 : age < 365 ? -6 : age < 1095 ? 8 : 16;
      out.push(
        evidence(
          "domain",
          "Domain age",
          `${rdap.source} registration date`,
          `Observed age: ${age} days (~${years} years)`,
          age < 180 ? "warning" : "pass",
          age < 30 ? "medium" : "none",
          0.9,
          weight,
          "Newly registered domains are heavily over-represented in fraud and phishing campaigns; long-lived domains carry accumulated operating history.",
        ),
      );
    }
    if (facts.expirationDate) {
      const daysLeft = Math.floor(
        (new Date(facts.expirationDate).getTime() - Date.now()) / 86_400_000,
      );
      out.push(
        evidence(
          "domain",
          "Registration expiry horizon",
          `${rdap.source} expiration event`,
          `Expires ${facts.expirationDate} (${daysLeft} days remaining)`,
          daysLeft < 45 ? "warning" : "pass",
          "none",
          0.8,
          daysLeft < 45 ? -6 : 4,
          "Long renewal horizons suggest ongoing commitment; imminent expiry is common for disposable infrastructure.",
        ),
      );
    }
  }

  out.push(
    evidence(
      "domain",
      "Top-level domain risk profile",
      "NOVAIN TLD abuse list (static, model-internal)",
      `TLD: .${tld}`,
      HIGH_RISK_TLDS.includes(tld) ? "warning" : "info",
      HIGH_RISK_TLDS.includes(tld) ? "medium" : "none",
      0.7,
      HIGH_RISK_TLDS.includes(tld) ? -12 : 0,
      "Some TLDs have disproportionate abuse rates; this is a weak prior, never a verdict on its own.",
    ),
  );

  const depth = labels.length;
  const hyphens = (domain.match(/-/g) ?? []).length;
  const digits = (domain.match(/\d/g) ?? []).length;
  const punycode = domain.includes("xn--");
  const structuralIssue = depth > 4 || hyphens > 2 || digits > 4 || punycode;
  out.push(
    evidence(
      "domain",
      "Hostname structure analysis",
      "Lexical analysis of the hostname",
      `labels=${depth}, hyphens=${hyphens}, digits=${digits}, punycode=${punycode}`,
      structuralIssue ? "warning" : "pass",
      punycode ? "medium" : structuralIssue ? "low" : "none",
      0.75,
      structuralIssue ? -14 : 5,
      "Deep subdomain chains, heavy hyphenation and IDN/punycode hostnames are typical of impersonation infrastructure.",
    ),
  );

  return out;
}

function identitySignals(html: string, body: string, domain: string): Evidence[] {
  const out: Evidence[] = [];

  if (!html) {
    out.push(
      evidence(
        "identity",
        "Operator identity disclosure",
        "Page content retrieval",
        "No page content could be retrieved, so operator identity could not be assessed",
        "unavailable",
        "none",
        0.2,
        0,
        "Identity remains unresolved. Unresolved identity caps the maximum achievable trust score.",
      ),
    );
    return out;
  }

  const found = IDENTITY_MARKERS.filter((m) => body.includes(m));
  out.push(
    evidence(
      "identity",
      "Legal and contact disclosure pages",
      "Fetched HTML of the landing page",
      found.length ? `Markers found: ${found.slice(0, 8).join(", ")}` : "No identity markers found",
      found.length >= 3 ? "pass" : found.length ? "warning" : "fail",
      found.length ? "none" : "medium",
      0.7,
      found.length >= 3 ? 14 : found.length ? 2 : -20,
      "Legitimate operators disclose who they are: legal terms, privacy policy and contact routes.",
    ),
  );

  const emails = Array.from(html.matchAll(/mailto:([^"'<>\s]+)/gi)).map((m) => m[1]);
  const phones = html.match(/(\+\d[\d\s().-]{7,}\d)/g) ?? [];
  out.push(
    evidence(
      "identity",
      "Reachable contact channels",
      "Fetched HTML of the landing page",
      `emails=${emails.length ? emails.slice(0, 3).join(", ") : "none"}; phone-like strings=${phones.length}`,
      emails.length || phones.length ? "pass" : "warning",
      emails.length || phones.length ? "none" : "low",
      0.6,
      emails.length || phones.length ? 8 : -8,
      "Published contact channels create accountability; complete absence is a common trait of throwaway sites.",
    ),
  );

  const onDomainEmail = emails.some((e) => e?.toLowerCase().includes(domain.split(".")[0] ?? "%%"));
  out.push(
    evidence(
      "identity",
      "Contact domain alignment",
      "Cross-check of published emails against the hostname",
      onDomainEmail
        ? "At least one contact address matches the site's own domain"
        : "No contact address aligned with the site's own domain",
      onDomainEmail ? "pass" : "warning",
      "none",
      0.55,
      onDomainEmail ? 8 : -4,
      "Contact addresses on the same organisational domain link the site to a controllable identity.",
    ),
  );

  out.push(
    evidence(
      "identity",
      "Independent legal-entity verification (registry)",
      "No company-registry data source is configured",
      "UNAVAILABLE — NOVAIN has no authorised registry connection for this target",
      "unavailable",
      "none",
      0.1,
      0,
      "Legal entity behind the site is NOT independently verified. No positive credit is awarded for a missing source.",
    ),
  );

  return out;
}

function reputationSignals(domain: string): Evidence[] {
  return [
    evidence(
      "reputation",
      "Malware / phishing blocklist status",
      "No threat-intelligence provider is configured",
      `UNAVAILABLE — no blocklist lookup performed for ${domain}`,
      "unavailable",
      "none",
      0.1,
      0,
      "Absence of a blocklist hit is NOT evidence of safety. Because the source is unavailable, no score is awarded in either direction.",
    ),
    evidence(
      "reputation",
      "Consumer review / complaint history",
      "No review-aggregation provider is configured",
      "UNAVAILABLE — no review data retrieved",
      "unavailable",
      "none",
      0.1,
      0,
      "Reputation cannot be established without an authorised external data source.",
    ),
  ];
}

function contentSignals(res: FetchResult, body: string): Evidence[] {
  const out: Evidence[] = [];
  const html = res.html;
  if (!html) {
    out.push(
      evidence(
        "content",
        "Landing page content",
        "Page content retrieval",
        `No content retrieved (${res.error ?? `status ${res.status}`})`,
        "unavailable",
        "none",
        0.2,
        0,
        "Nothing could be analysed, so no content-based conclusion is drawn.",
      ),
    );
    return out;
  }

  const title = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html)?.[1]?.trim() ?? "";
  out.push(
    evidence(
      "content",
      "Document metadata",
      "Fetched HTML of the landing page",
      `title="${title || "(missing)"}"; content length ${html.length} bytes`,
      title ? "info" : "warning",
      "none",
      0.8,
      title ? 4 : -6,
      "A meaningful title and substantive content indicate a maintained site rather than a parked or thrown-together page.",
    ),
  );

  const hits = SUSPICIOUS_CONTENT.filter((k) => body.includes(k));
  out.push(
    evidence(
      "content",
      "High-risk solicitation language",
      "Keyword analysis of visible page text",
      hits.length ? `Matched phrases: ${hits.join(", ")}` : "No high-risk solicitation phrases found",
      hits.length ? "fail" : "pass",
      hits.length >= 3 ? "high" : hits.length ? "medium" : "none",
      0.75,
      hits.length ? -16 * Math.min(hits.length, 3) : 8,
      "Urgency, wallet-connection and reward-claim language is strongly associated with scam and phishing pages.",
    ),
  );

  const passwordField = /<input[^>]+type=["']?password/i.test(html);
  const externalForm = /<form[^>]+action=["']https?:\/\/(?!(?:www\.)?)/i.test(html);
  out.push(
    evidence(
      "content",
      "Credential collection surfaces",
      "Form analysis of the landing page",
      `password input=${passwordField}; form posting to an external origin=${externalForm}`,
      externalForm ? "fail" : passwordField ? "warning" : "pass",
      externalForm ? "high" : "none",
      0.7,
      externalForm ? -25 : passwordField ? -4 : 3,
      "Credential fields are normal for real services, but posting them to a third-party origin is a hallmark of credential harvesting.",
    ),
  );

  const metaRefresh = /<meta[^>]+http-equiv=["']?refresh/i.test(html);
  const hiddenIframes = (html.match(/<iframe[^>]*(display:\s*none|hidden)[^>]*>/gi) ?? []).length;
  out.push(
    evidence(
      "content",
      "Cloaking and redirect techniques",
      "Static analysis of the returned markup",
      `meta refresh=${metaRefresh}; hidden iframes=${hiddenIframes}`,
      metaRefresh || hiddenIframes ? "warning" : "pass",
      metaRefresh || hiddenIframes ? "medium" : "none",
      0.65,
      metaRefresh || hiddenIframes ? -14 : 4,
      "Automatic refreshes and hidden frames are used to hide the real destination from analysis tools.",
    ),
  );

  return out;
}

function anomalySignals(
  url: string,
  res: FetchResult,
  body: string,
  domainEvidence: Evidence[],
): Evidence[] {
  const out: Evidence[] = [];
  const host = new URL(url).hostname.toLowerCase();

  const finalHost = res.ok ? new URL(res.finalUrl).hostname.toLowerCase() : host;
  const offHost = finalHost.replace(/^www\./, "") !== host.replace(/^www\./, "");
  out.push(
    evidence(
      "anomaly",
      "Redirect destination consistency",
      "Observed redirect chain",
      offHost
        ? `Requested ${host} but landed on ${finalHost}`
        : `Request stayed on ${finalHost}`,
      offHost ? "warning" : "pass",
      offHost ? "medium" : "none",
      0.8,
      offHost ? -12 : 4,
      "Silent cross-host redirection can indicate traffic brokering, hijacked domains or scam funnels.",
    ),
  );

  const brands = ["paypal", "apple", "microsoft", "binance", "metamask", "netflix", "amazon", "coinbase", "google"];
  const impersonated = brands.filter(
    (b) => (host.includes(b) || body.includes(b)) && !host.replace(/^www\./, "").startsWith(`${b}.`),
  );
  const brandInHostname = brands.filter((b) => host.includes(b) && !host.endsWith(`${b}.com`));
  out.push(
    evidence(
      "anomaly",
      "Brand impersonation cross-check",
      "Cross-check of hostname against page content and known brand list",
      brandInHostname.length
        ? `Brand terms embedded in a non-official hostname: ${brandInHostname.join(", ")}`
        : impersonated.length
          ? `Brand terms mentioned in content: ${impersonated.slice(0, 4).join(", ")}`
          : "No brand impersonation indicators detected",
      brandInHostname.length ? "fail" : "pass",
      brandInHostname.length ? "critical" : "none",
      0.7,
      brandInHostname.length ? -40 : 4,
      "A well-known brand name inside a hostname the brand does not own is one of the strongest phishing indicators.",
    ),
  );

  const youngDomain = domainEvidence.some(
    (e) => e.check === "Domain age" && /Observed age: (\d+) days/.test(e.observation) && Number(/Observed age: (\d+) days/.exec(e.observation)?.[1]) < 90,
  );
  const asksCredentials = /<input[^>]+type=["']?password/i.test(res.html);
  out.push(
    evidence(
      "anomaly",
      "Composite risk pattern (new domain + credential capture)",
      "Correlation of domain-age and content evidence",
      `young domain=${youngDomain}; credential capture=${asksCredentials}`,
      youngDomain && asksCredentials ? "fail" : "pass",
      youngDomain && asksCredentials ? "high" : "none",
      0.7,
      youngDomain && asksCredentials ? -30 : 3,
      "A very recently registered domain that already collects credentials matches the standard phishing lifecycle.",
    ),
  );

  return out;
}

/* ---------------------------------- scoring --------------------------------- */

function worstOutcome(items: Evidence[]): SignalOutcome {
  if (!items.length) return "unavailable";
  if (items.every((i) => i.outcome === "unavailable")) return "unavailable";
  if (items.some((i) => i.outcome === "fail")) return "fail";
  if (items.some((i) => i.outcome === "warning")) return "warning";
  if (items.some((i) => i.outcome === "pass")) return "pass";
  return "info";
}

function scoreCategories(all: Evidence[]): Record<SignalCategory, CategoryResult> {
  const categories = Object.keys(CATEGORY_WEIGHTS) as SignalCategory[];
  const result = {} as Record<SignalCategory, CategoryResult>;
  for (const category of categories) {
    const items = all.filter((e) => e.category === category);
    const scored = items.filter((e) => e.outcome !== "unavailable");
    const delta = scored.reduce((sum, e) => sum + e.weight * e.confidence, 0);
    const available = scored.length > 0;
    result[category] = {
      category,
      score: available ? Math.max(0, Math.min(100, Math.round(50 + delta))) : null,
      outcome: worstOutcome(items),
      weight: CATEGORY_WEIGHTS[category],
      confidence: items.length
        ? Number((items.reduce((s, e) => s + e.confidence, 0) / items.length).toFixed(2))
        : 0,
      evidence_ids: items.map((e) => e.id),
    };
  }
  return result;
}

function applyGates(
  raw: number,
  all: Evidence[],
  categories: Record<SignalCategory, CategoryResult>,
): { score: number; gates: RiskGate[] } {
  const gates: RiskGate[] = [];

  const identityUnresolved =
    categories.identity.outcome === "unavailable" ||
    categories.identity.outcome === "fail" ||
    (categories.identity.score ?? 0) < 50;
  if (identityUnresolved) {
    gates.push({
      gate: "identity_unresolved",
      cap: 69,
      reason:
        "Operator identity is not independently resolved, so the target cannot exceed a medium trust score regardless of other signals.",
      evidence_ids: categories.identity.evidence_ids,
    });
  }

  const critical = all.filter((e) => e.severity === "critical" && e.outcome === "fail");
  if (critical.length) {
    gates.push({
      gate: "critical_security_indicator",
      cap: 15,
      reason: "A critical security indicator was observed.",
      evidence_ids: critical.map((e) => e.id),
    });
  }

  const high = all.filter((e) => e.severity === "high" && e.outcome === "fail");
  if (high.length) {
    gates.push({
      gate: "high_severity_indicator",
      cap: 35,
      reason: "One or more high-severity risk indicators were observed.",
      evidence_ids: high.map((e) => e.id),
    });
  }

  const unreachable = all.some(
    (e) => e.category === "infrastructure" && e.check === "HTTPS connection" && e.outcome === "fail",
  );
  if (unreachable) {
    gates.push({
      gate: "target_unreachable",
      cap: 40,
      reason: "The target could not be reached, so almost no evidence exists to support trust.",
      evidence_ids: all.filter((e) => e.check === "HTTPS connection").map((e) => e.id),
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

function statusFor(score: number, gates: RiskGate[]): VerificationStatus {
  if (gates.some((g) => g.gate === "critical_security_indicator") || score < 20) return "CRITICAL";
  if (score < 40) return "HIGH_RISK";
  if (score < 60) return "WARNING";
  if (score < 80) return "UNVERIFIED";
  return "VERIFIED";
}

function recommend(status: VerificationStatus, gates: RiskGate[]): string {
  const identity = gates.some((g) => g.gate === "identity_unresolved");
  switch (status) {
    case "CRITICAL":
      return "Do not transact. Critical risk indicators were observed in the collected evidence.";
    case "HIGH_RISK":
      return "Avoid payments or credential entry. Independent verification through another channel is required first.";
    case "WARNING":
      return "Proceed only with strong safeguards: verify the operator out-of-band and use reversible payment methods.";
    case "UNVERIFIED":
      return identity
        ? "No disqualifying signals found, but the operator's identity is unresolved. Confirm the legal entity before payment."
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

  const body = text(httpsRes.html);
  const infra = infrastructureSignals(url, httpsRes, plainRes);
  const domainEv = await domainSignals(domain);
  const identity = identitySignals(httpsRes.html, body, domain);
  const reputation = reputationSignals(domain);
  const content = contentSignals(httpsRes, body);
  const anomaly = anomalySignals(url, httpsRes, body, domainEv);

  const all = [...infra, ...domainEv, ...identity, ...reputation, ...content, ...anomaly];
  const categories = scoreCategories(all);

  const scored = (Object.values(categories) as CategoryResult[]).filter((c) => c.score !== null);
  const totalWeight = scored.reduce((s, c) => s + c.weight, 0) || 1;
  const raw = Math.round(
    scored.reduce((s, c) => s + (c.score as number) * c.weight, 0) / totalWeight,
  );

  const { score, gates } = applyGates(raw, all, categories);
  const availableWeight = totalWeight / Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0);
  const evidenceConfidence =
    all.reduce((s, e) => s + e.confidence, 0) / (all.length || 1);
  const confidence = Number((availableWeight * evidenceConfidence).toFixed(2));

  const checks = Object.fromEntries(
    (Object.values(categories) as CategoryResult[]).map((c) => [c.category, c.outcome]),
  ) as Record<SignalCategory, SignalOutcome>;

  const status = statusFor(score, gates);

  return {
    verification_id: crypto.randomUUID(),
    target: url,
    domain,
    status,
    risk_level: riskLevel(score),
    trust_score: score,
    raw_score: raw,
    confidence,
    capped: score < raw,
    applied_gates: gates,
    categories,
    checks,
    evidence: all,
    recommendation: recommend(status, gates),
    duration_ms: Date.now() - started,
    checked_at: new Date().toISOString(),
    model_version: MODEL_VERSION,
  };
}
