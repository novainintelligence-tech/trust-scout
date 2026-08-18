import { makeEvidence, type SourceAdapter } from "./base";

const IDENTITY_MARKERS = [
  "about us", "about", "contact", "imprint", "impressum", "legal", "terms",
  "privacy", "company", "registered office", "vat", "registration number",
];

const SRC = "Fetched HTML of the landing page";

/** Identity engine: who operates this service, and can that be corroborated? */
export const identitySource: SourceAdapter = {
  id: "identity",
  label: "Identity engine",
  async run(ctx) {
    const evidence = [];
    const html = ctx.https.html;

    if (!html) {
      evidence.push(
        makeEvidence("identity", {
          source: "Page content retrieval",
          category: "identity",
          signal: "Operator identity disclosure",
          observation: "No page content could be retrieved, so operator identity could not be assessed",
          result: "unknown",
          confidence: 0,
          explanation:
            "Identity is UNKNOWN — not bad. Unknown identity still caps the maximum achievable trust score, because trust must be positively established.",
        }),
      );
    } else {
      const found = IDENTITY_MARKERS.filter((m) => ctx.body.includes(m));
      evidence.push(
        makeEvidence("identity", {
          source: SRC,
          category: "identity",
          signal: "Legal and contact disclosure pages",
          observation: found.length ? `Markers found: ${found.slice(0, 8).join(", ")}` : "No identity markers found",
          result: found.length >= 3 ? "pass" : found.length ? "warning" : "fail",
          severity: found.length ? "none" : "medium",
          confidence: 0.7,
          weight: found.length >= 3 ? 14 : found.length ? 2 : -20,
          explanation:
            "Legitimate operators disclose who they are: legal terms, privacy policy and contact routes.",
        }),
      );

      const emails = Array.from(html.matchAll(/mailto:([^"'<>\s]+)/gi)).map((m) => m[1] ?? "");
      const phones = html.match(/(\+\d[\d\s().-]{7,}\d)/g) ?? [];
      evidence.push(
        makeEvidence("identity", {
          source: SRC,
          category: "identity",
          signal: "Reachable contact channels",
          observation: `emails=${emails.length ? emails.slice(0, 3).join(", ") : "none"}; phone-like strings=${phones.length}`,
          result: emails.length || phones.length ? "pass" : "warning",
          severity: emails.length || phones.length ? "none" : "low",
          confidence: 0.6,
          weight: emails.length || phones.length ? 8 : -8,
          explanation:
            "Published contact channels create accountability; complete absence is common on throwaway sites.",
        }),
      );

      const label = ctx.domain.split(".")[0] ?? "%%";
      const aligned = emails.some((e) => e.toLowerCase().includes(label));
      evidence.push(
        makeEvidence("identity", {
          source: "Cross-check of published emails against the hostname",
          category: "identity",
          signal: "Contact domain alignment",
          observation: emails.length
            ? aligned
              ? "At least one contact address matches the site's own domain"
              : "No published contact address aligned with the site's own domain"
            : "No published email addresses to cross-check",
          result: emails.length ? (aligned ? "pass" : "warning") : "unknown",
          confidence: emails.length ? 0.55 : 0,
          weight: aligned ? 8 : -4,
          explanation:
            "Contact addresses on the same organisational domain link the site to a controllable identity.",
        }),
      );
    }

    // Independent registry corroboration is not configured — explicitly UNKNOWN.
    evidence.push(
      makeEvidence("identity", {
        source: "No authorised company-registry connector configured",
        category: "identity",
        signal: "Independent legal-entity verification",
        observation: "UNKNOWN — NOVAIN has no authorised registry connection for this target",
        result: "unknown",
        confidence: 0,
        explanation:
          "The legal entity behind the site is neither confirmed nor disproven. No credit and no penalty are applied for a missing source; the identity risk gate still applies.",
      }),
    );

    return {
      status: html ? "ok" : "unavailable",
      detail: html ? "Page-level identity signals collected" : "No page content",
      evidence,
    };
  },
};
