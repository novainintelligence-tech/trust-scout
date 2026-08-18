import { fetchJson, makeEvidence, type SourceAdapter } from "./base";

interface CrtEntry {
  issuer_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
}

const SRC = "crt.sh — public Certificate Transparency logs";

export const tlsSource: SourceAdapter = {
  id: "tls",
  label: "Certificate Transparency (crt.sh)",
  async run(ctx) {
    const evidence = [];
    const res = await fetchJson<CrtEntry[]>(
      `https://crt.sh/?q=${encodeURIComponent(ctx.domain)}&output=json&exclude=expired`,
      { timeoutMs: 10000 },
    );

    if (!res.ok || !Array.isArray(res.data)) {
      evidence.push(
        makeEvidence("tls", {
          source: SRC,
          category: "infrastructure",
          signal: "Certificate issuance history",
          observation: `Certificate Transparency lookup unavailable: ${res.error ?? "unparsable response"}`,
          result: "unknown",
          confidence: 0,
          explanation:
            "Certificate history is UNKNOWN. Absence of CT data is not treated as either good or bad.",
        }),
      );
      return { status: "unavailable", detail: res.error ?? "CT lookup failed", evidence };
    }

    const entries = res.data;
    const dates = entries
      .map((e) => (e.not_before ? Date.parse(e.not_before) : NaN))
      .filter((n) => Number.isFinite(n));
    const earliest = dates.length ? new Date(Math.min(...dates)) : null;
    const historyDays = earliest ? Math.floor((Date.now() - earliest.getTime()) / 86_400_000) : null;
    const issuers = Array.from(
      new Set(
        entries
          .map((e) => /O=([^,]+)/.exec(e.issuer_name ?? "")?.[1] ?? e.issuer_name ?? "")
          .filter(Boolean),
      ),
    );

    evidence.push(
      makeEvidence("tls", {
        source: SRC,
        category: "infrastructure",
        signal: "Certificate issuance history",
        observation: `${entries.length} unexpired CT entries; earliest issuance ${earliest ? earliest.toISOString().slice(0, 10) : "unknown"} (${historyDays ?? "?"} days of history); issuers: ${issuers.slice(0, 3).join(", ") || "unknown"}`,
        result: historyDays === null ? "unknown" : historyDays > 365 ? "pass" : historyDays > 90 ? "info" : "warning",
        severity: historyDays !== null && historyDays < 30 ? "low" : "none",
        confidence: 0.8,
        weight: historyDays === null ? 0 : historyDays > 365 ? 10 : historyDays > 90 ? 3 : -8,
        explanation:
          "A long, continuous certificate history is hard to fabricate and shows the hostname has been operated over time. A certificate itself proves encryption only — never trustworthiness.",
      }),
    );

    const wildcardOnly =
      entries.length > 0 && entries.every((e) => (e.name_value ?? "").includes("*"));
    evidence.push(
      makeEvidence("tls", {
        source: SRC,
        category: "infrastructure",
        signal: "Certificate subject coverage",
        observation: `${entries.length} entries; wildcard-only coverage=${wildcardOnly}`,
        result: entries.length ? "info" : "unknown",
        confidence: entries.length ? 0.6 : 0,
        weight: 0,
        explanation:
          "Recorded for correlation and future analysis; subject coverage alone does not move the score.",
      }),
    );

    return { status: "ok", detail: `${entries.length} CT entries`, evidence };
  },
};
