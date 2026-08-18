import { fetchJson, makeEvidence, resolveDns, type SourceAdapter } from "./base";

/**
 * Reputation intelligence from independent, publicly documented sources.
 * Every lookup that fails is reported as UNKNOWN — never as "clean".
 */
export const reputationSource: SourceAdapter = {
  id: "reputation",
  label: "Reputation intelligence",
  async run(ctx) {
    const evidence = [];
    let available = 0;

    /* 1. Security-filtering resolver comparison (Cloudflare 1.1.1.2 malware/phishing filter). */
    const [normal, filtered] = await Promise.all([
      resolveDns(ctx.domain, "A"),
      resolveDns(ctx.domain, "A", "https://security.cloudflare-dns.com/dns-query"),
    ]);
    if (normal.ok && filtered.ok && normal.data && filtered.data) {
      available += 1;
      const normalIps = (normal.data.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
      const filteredIps = (filtered.data.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
      const blocked =
        normalIps.length > 0 &&
        (filteredIps.length === 0 || filteredIps.every((ip) => ip === "0.0.0.0" || ip === "::"));
      evidence.push(
        makeEvidence("reputation", {
          source: "Cloudflare security resolver (1.1.1.2 malware/phishing filtering) vs. unfiltered resolution",
          category: "reputation",
          signal: "Threat-filtering resolver verdict",
          observation: blocked
            ? `Unfiltered resolution returned ${normalIps.slice(0, 2).join(", ")} but the security resolver blocked the domain (${filteredIps.join(", ") || "no answer"})`
            : `Domain resolves identically on the unfiltered and the security-filtering resolver (${filteredIps.slice(0, 2).join(", ") || "no A record"})`,
          result: blocked ? "fail" : "pass",
          severity: blocked ? "critical" : "none",
          confidence: blocked ? 0.85 : 0.6,
          weight: blocked ? -60 : 10,
          explanation: blocked
            ? "A major security resolver classifies this domain as malware or phishing infrastructure."
            : "The domain is not currently filtered by a widely deployed threat-blocking resolver. This is a negative check: it lowers suspicion but does not by itself prove legitimacy.",
        }),
      );
    } else {
      evidence.push(
        makeEvidence("reputation", {
          source: "Cloudflare security resolver (1.1.1.2)",
          category: "reputation",
          signal: "Threat-filtering resolver verdict",
          observation: `Comparison unavailable: ${filtered.error ?? normal.error ?? "no response"}`,
          result: "unknown",
          confidence: 0,
          explanation: "The blocklist resolver could not be queried, so blocklist status is UNKNOWN.",
        }),
      );
    }

    /* 2. Google Transparency Report / Safe Browsing requires an API key — explicitly unknown. */
    evidence.push(
      makeEvidence("reputation", {
        source: "Google Safe Browsing API (no API key configured)",
        category: "reputation",
        signal: "Malware / social-engineering blocklist",
        observation: "UNKNOWN — no authorised Safe Browsing lookup performed",
        result: "unknown",
        confidence: 0,
        explanation:
          "Absence of a blocklist hit is NOT evidence of safety. Because this source is not configured, no score is awarded in either direction.",
      }),
    );

    /* 3. Consumer review / complaint aggregation — requires a licensed feed. */
    evidence.push(
      makeEvidence("reputation", {
        source: "Consumer review aggregation (no licensed provider configured)",
        category: "reputation",
        signal: "Consumer review and complaint history",
        observation: "UNKNOWN — no review data retrieved",
        result: "unknown",
        confidence: 0,
        explanation:
          "Reputation from public reviews cannot be established without an authorised data source; scraping providers in breach of their terms is out of scope.",
      }),
    );

    /* 4. Public suffix / hosting neighbourhood via reverse DNS of the resolved IP. */
    const ip = (normal.data?.Answer ?? []).find((r) => r.type === 1)?.data;
    if (ip) {
      const ptr = await resolveDns(`${ip.split(".").reverse().join(".")}.in-addr.arpa`, "PTR");
      const ptrName = (ptr.data?.Answer ?? []).find((r) => r.type === 12)?.data ?? null;
      if (ptr.ok) {
        available += 1;
        evidence.push(
          makeEvidence("reputation", {
            source: "Reverse DNS (PTR) of the resolved address via Google Public DNS",
            category: "reputation",
            signal: "Hosting provider attribution",
            observation: ptrName ? `${ip} → ${ptrName}` : `${ip} has no PTR record`,
            result: ptrName ? "info" : "info",
            confidence: 0.5,
            weight: ptrName ? 2 : 0,
            explanation:
              "Attributable hosting makes abuse reporting possible. Recorded mainly as correlation context.",
          }),
        );
      }
    }

    return {
      status: available > 0 ? "ok" : "unavailable",
      detail: `${available} independent reputation source(s) answered`,
      evidence,
    };
  },
};

/** Domain history via the Internet Archive — an independent, public dataset. */
export const historySource: SourceAdapter = {
  id: "history",
  label: "Internet Archive history",
  async run(ctx) {
    const evidence = [];
    const res = await fetchJson<string[][]>(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(ctx.domain)}&output=json&fl=timestamp&limit=1&filter=statuscode:200`,
      { timeoutMs: 9000 },
    );
    const first = Array.isArray(res.data) && res.data.length > 1 ? res.data[1]?.[0] : null;

    if (!res.ok || !Array.isArray(res.data)) {
      evidence.push(
        makeEvidence("history", {
          source: "Internet Archive Wayback CDX API",
          category: "reputation",
          signal: "Historical web presence",
          observation: `Archive lookup unavailable: ${res.error ?? "unparsable response"}`,
          result: "unknown",
          confidence: 0,
          explanation: "Historical presence is UNKNOWN; no score applied.",
        }),
      );
      return { status: "unavailable", detail: res.error ?? "archive unavailable", evidence };
    }

    if (!first) {
      evidence.push(
        makeEvidence("history", {
          source: "Internet Archive Wayback CDX API",
          category: "reputation",
          signal: "Historical web presence",
          observation: "No archived successful snapshot found for this domain",
          result: "warning",
          severity: "low",
          confidence: 0.6,
          weight: -8,
          explanation:
            "An established public service usually leaves an archival trail. Absence is weak evidence of a very new or low-visibility site, not proof of fraud.",
        }),
      );
      return { status: "ok", detail: "No snapshots", evidence };
    }

    const y = Number(first.slice(0, 4));
    const m = Number(first.slice(4, 6)) - 1;
    const d = Number(first.slice(6, 8));
    const firstDate = new Date(Date.UTC(y, m, d));
    const years = (Date.now() - firstDate.getTime()) / (365 * 86_400_000);
    evidence.push(
      makeEvidence("history", {
        source: "Internet Archive Wayback CDX API",
        category: "reputation",
        signal: "Historical web presence",
        observation: `First archived successful snapshot: ${firstDate.toISOString().slice(0, 10)} (~${years.toFixed(1)} years of public history)`,
        result: years >= 2 ? "pass" : years >= 0.5 ? "info" : "warning",
        confidence: 0.75,
        weight: years >= 5 ? 18 : years >= 2 ? 12 : years >= 0.5 ? 4 : -6,
        explanation:
          "A long, independently archived history is expensive to fake and correlates strongly with genuine long-running operations.",
      }),
    );

    return { status: "ok", detail: `First snapshot ${firstDate.toISOString().slice(0, 10)}`, evidence };
  },
};
