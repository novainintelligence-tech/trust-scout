import { fetchRdap, parseRdap } from "../collectors";
import { makeEvidence, type SourceAdapter } from "./base";

const HIGH_RISK_TLDS = [
  "zip", "mov", "top", "xyz", "gq", "cf", "ml", "tk", "work", "click", "country", "loan", "rest", "quest",
];

export const rdapSource: SourceAdapter = {
  id: "rdap",
  label: "RDAP registry (IANA bootstrap)",
  async run(ctx) {
    const src = "rdap.org (IANA RDAP bootstrap)";
    const evidence = [];
    const labels = ctx.domain.split(".");
    const tld = labels[labels.length - 1] ?? "";

    const rdap = await fetchRdap(ctx.domain);
    const facts = rdap.ok ? parseRdap(rdap.data) : null;

    if (!facts) {
      evidence.push(
        makeEvidence("rdap", {
          source: src,
          category: "domain",
          signal: "Domain registration record",
          observation: `Registration data could not be retrieved: ${rdap.error ?? "no parsable record"}`,
          result: "unknown",
          confidence: 0,
          explanation:
            "Registration age, registrar and status are UNKNOWN. No score is applied in either direction.",
        }),
      );
    } else {
      evidence.push(
        makeEvidence("rdap", {
          source: src,
          category: "domain",
          signal: "Domain registration record",
          observation: `Registered: yes; created ${facts.registrationDate ?? "unknown"}; registrar ${facts.registrar ?? "unknown"}; statuses ${facts.statuses.join(", ") || "none"}`,
          result: "pass",
          confidence: 0.9,
          weight: 4,
          explanation: "An authoritative registry record exists for this domain.",
        }),
      );
      if (facts.ageDays !== null) {
        const age = facts.ageDays;
        const weight = age < 30 ? -30 : age < 180 ? -18 : age < 365 ? -6 : age < 1095 ? 8 : 16;
        evidence.push(
          makeEvidence("rdap", {
            source: `${src} — registration event`,
            category: "domain",
            signal: "Domain age",
            observation: `Observed age: ${age} days (~${(age / 365).toFixed(1)} years)`,
            result: age < 180 ? "warning" : "pass",
            severity: age < 30 ? "medium" : "none",
            confidence: 0.9,
            weight,
            explanation:
              "Newly registered domains are heavily over-represented in fraud campaigns; long-lived domains carry accumulated operating history.",
          }),
        );
      }
      if (facts.expirationDate) {
        const daysLeft = Math.floor(
          (new Date(facts.expirationDate).getTime() - Date.now()) / 86_400_000,
        );
        evidence.push(
          makeEvidence("rdap", {
            source: `${src} — expiration event`,
            category: "domain",
            signal: "Registration expiry horizon",
            observation: `Expires ${facts.expirationDate} (${daysLeft} days remaining)`,
            result: daysLeft < 45 ? "warning" : "pass",
            confidence: 0.8,
            weight: daysLeft < 45 ? -6 : 4,
            explanation:
              "Long renewal horizons suggest ongoing commitment; imminent expiry is common for disposable infrastructure.",
          }),
        );
      }
    }

    const risky = HIGH_RISK_TLDS.includes(tld);
    evidence.push(
      makeEvidence("rdap", {
        source: "NOVAIN TLD abuse prior (static, model-internal)",
        category: "domain",
        signal: "Top-level domain risk profile",
        observation: `TLD: .${tld}`,
        result: risky ? "warning" : "info",
        severity: risky ? "medium" : "none",
        confidence: 0.7,
        weight: risky ? -12 : 0,
        explanation:
          "Some TLDs have disproportionate abuse rates; this is a weak prior, never a verdict on its own.",
      }),
    );

    const depth = labels.length;
    const hyphens = (ctx.domain.match(/-/g) ?? []).length;
    const digits = (ctx.domain.match(/\d/g) ?? []).length;
    const punycode = ctx.domain.includes("xn--");
    const structural = depth > 4 || hyphens > 2 || digits > 4 || punycode;
    evidence.push(
      makeEvidence("rdap", {
        source: "Lexical analysis of the hostname",
        category: "domain",
        signal: "Hostname structure analysis",
        observation: `labels=${depth}, hyphens=${hyphens}, digits=${digits}, punycode=${punycode}`,
        result: structural ? "warning" : "pass",
        severity: punycode ? "medium" : structural ? "low" : "none",
        confidence: 0.75,
        weight: structural ? -14 : 5,
        explanation:
          "Deep subdomain chains, heavy hyphenation and IDN/punycode hostnames are typical of impersonation infrastructure.",
      }),
    );

    return {
      status: facts ? "ok" : "unavailable",
      detail: facts ? "Registry record retrieved" : (rdap.error ?? "No registry record"),
      evidence,
    };
  },
};
