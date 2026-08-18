import type { Evidence } from "../types";
import { makeEvidence, type SourceAdapter } from "./base";

const BRANDS = [
  "paypal", "apple", "microsoft", "binance", "metamask", "netflix", "amazon", "coinbase", "google",
];

/** Correlation layer: runs after the primary sources and cross-checks their evidence. */
export const anomalySource: SourceAdapter = {
  id: "anomaly",
  label: "Correlation and anomaly engine",
  async run(ctx, collected: Evidence[]) {
    const evidence = [];
    const host = ctx.hostname;

    if (ctx.https.ok) {
      let finalHost = host;
      try {
        finalHost = new URL(ctx.https.finalUrl).hostname.toLowerCase();
      } catch {
        /* keep original */
      }
      const offHost = finalHost.replace(/^www\./, "") !== host.replace(/^www\./, "");
      evidence.push(
        makeEvidence("anomaly", {
          source: "Observed redirect chain",
          category: "anomaly",
          signal: "Redirect destination consistency",
          observation: offHost ? `Requested ${host} but landed on ${finalHost}` : `Request stayed on ${finalHost}`,
          result: offHost ? "warning" : "pass",
          severity: offHost ? "medium" : "none",
          confidence: 0.8,
          weight: offHost ? -12 : 4,
          explanation:
            "Silent cross-host redirection can indicate traffic brokering, hijacked domains or scam funnels.",
        }),
      );
    } else {
      evidence.push(
        makeEvidence("anomaly", {
          source: "Observed redirect chain",
          category: "anomaly",
          signal: "Redirect destination consistency",
          observation: "Target unreachable — redirect behaviour could not be observed",
          result: "unknown",
          confidence: 0,
          explanation: "No conclusion drawn about redirect behaviour.",
        }),
      );
    }

    const brandInHostname = BRANDS.filter((b) => host.includes(b) && !host.endsWith(`${b}.com`));
    const brandInBody = BRANDS.filter((b) => ctx.body.includes(b));
    evidence.push(
      makeEvidence("anomaly", {
        source: "Cross-check of hostname against page content and a known-brand list",
        category: "anomaly",
        signal: "Brand impersonation cross-check",
        observation: brandInHostname.length
          ? `Brand terms embedded in a non-official hostname: ${brandInHostname.join(", ")}`
          : brandInBody.length
            ? `Brand terms mentioned in content only: ${brandInBody.slice(0, 4).join(", ")}`
            : "No brand impersonation indicators detected",
        result: brandInHostname.length ? "fail" : "pass",
        severity: brandInHostname.length ? "critical" : "none",
        confidence: 0.7,
        weight: brandInHostname.length ? -40 : 4,
        explanation:
          "A well-known brand name inside a hostname the brand does not own is one of the strongest phishing indicators.",
      }),
    );

    const ageEvidence = collected.find((e) => e.signal === "Domain age");
    const ageDays = ageEvidence ? Number(/Observed age: (\d+) days/.exec(ageEvidence.observation)?.[1]) : NaN;
    const asksCredentials = /<input[^>]+type=["']?password/i.test(ctx.https.html);
    if (!Number.isFinite(ageDays)) {
      evidence.push(
        makeEvidence("anomaly", {
          source: "Correlation of domain-age and content evidence",
          category: "anomaly",
          signal: "Composite pattern: new domain + credential capture",
          observation: "Domain age is UNKNOWN, so this correlation could not be evaluated",
          result: "unknown",
          confidence: 0,
          explanation: "Composite pattern requires domain age; no conclusion drawn.",
        }),
      );
    } else {
      const young = ageDays < 90;
      evidence.push(
        makeEvidence("anomaly", {
          source: "Correlation of domain-age and content evidence",
          category: "anomaly",
          signal: "Composite pattern: new domain + credential capture",
          observation: `domain age=${ageDays} days; credential capture=${asksCredentials}`,
          result: young && asksCredentials ? "fail" : "pass",
          severity: young && asksCredentials ? "high" : "none",
          confidence: 0.7,
          weight: young && asksCredentials ? -30 : 3,
          explanation:
            "A very recently registered domain that already collects credentials matches the standard phishing lifecycle.",
        }),
      );
    }

    const fails = collected.filter((e) => e.result === "fail");
    const categoriesFailing = new Set(fails.map((e) => e.category));
    evidence.push(
      makeEvidence("anomaly", {
        source: "Cross-source evidence correlation",
        category: "anomaly",
        signal: "Independent-source agreement",
        observation: `${fails.length} failing signal(s) across ${categoriesFailing.size} independent categor(y/ies)`,
        result: categoriesFailing.size >= 3 ? "fail" : categoriesFailing.size === 2 ? "warning" : "pass",
        severity: categoriesFailing.size >= 3 ? "high" : categoriesFailing.size === 2 ? "medium" : "none",
        confidence: 0.7,
        weight: categoriesFailing.size >= 3 ? -25 : categoriesFailing.size === 2 ? -10 : 5,
        explanation:
          "Single negative signals are noisy. Independent sources failing at the same time is the strongest evidence of genuine risk.",
      }),
    );

    return { status: "ok", detail: `${evidence.length} correlation signals`, evidence };
  },
};
