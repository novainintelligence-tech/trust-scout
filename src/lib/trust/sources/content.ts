import { makeEvidence, type SourceAdapter } from "./base";

const SUSPICIOUS_CONTENT = [
  "connect wallet", "seed phrase", "private key", "gift card", "wire transfer",
  "verify your account", "your account has been suspended", "claim your reward",
  "double your", "airdrop", "act now", "limited time only",
];

const SRC = "Fetched HTML of the landing page";

export const contentSource: SourceAdapter = {
  id: "content",
  label: "Page content analysis",
  async run(ctx) {
    const evidence = [];
    const html = ctx.https.html;

    if (!html) {
      evidence.push(
        makeEvidence("content", {
          source: SRC,
          category: "content",
          signal: "Landing page content",
          observation: `No content retrieved (${ctx.https.error ?? `status ${ctx.https.status}`})`,
          result: "unknown",
          confidence: 0,
          explanation: "Nothing could be analysed, so no content-based conclusion is drawn.",
        }),
      );
      return { status: "unavailable", detail: "No page content", evidence };
    }

    const title = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html)?.[1]?.trim() ?? "";
    evidence.push(
      makeEvidence("content", {
        source: SRC,
        category: "content",
        signal: "Document metadata",
        observation: `title="${title || "(missing)"}"; content length ${html.length} bytes`,
        result: title ? "info" : "warning",
        confidence: 0.8,
        weight: title ? 4 : -6,
        explanation:
          "A meaningful title and substantive content indicate a maintained site rather than a parked page.",
      }),
    );

    const hits = SUSPICIOUS_CONTENT.filter((k) => ctx.body.includes(k));
    evidence.push(
      makeEvidence("content", {
        source: "Keyword analysis of visible page text",
        category: "content",
        signal: "High-risk solicitation language",
        observation: hits.length ? `Matched phrases: ${hits.join(", ")}` : "No high-risk solicitation phrases found",
        result: hits.length ? "fail" : "pass",
        severity: hits.length >= 3 ? "high" : hits.length ? "medium" : "none",
        confidence: 0.75,
        weight: hits.length ? -16 * Math.min(hits.length, 3) : 8,
        explanation:
          "Urgency, wallet-connection and reward-claim language is strongly associated with scam and phishing pages.",
      }),
    );

    const passwordField = /<input[^>]+type=["']?password/i.test(html);
    const externalForm = /<form[^>]+action=["']https?:\/\/(?!(?:www\.)?)/i.test(html);
    evidence.push(
      makeEvidence("content", {
        source: "Form analysis of the landing page",
        category: "content",
        signal: "Credential collection surfaces",
        observation: `password input=${passwordField}; form posting to an external origin=${externalForm}`,
        result: externalForm ? "fail" : passwordField ? "warning" : "pass",
        severity: externalForm ? "high" : "none",
        confidence: 0.7,
        weight: externalForm ? -25 : passwordField ? -4 : 3,
        explanation:
          "Credential fields are normal for real services, but posting them to a third-party origin is a hallmark of credential harvesting.",
      }),
    );

    const metaRefresh = /<meta[^>]+http-equiv=["']?refresh/i.test(html);
    const hiddenIframes = (html.match(/<iframe[^>]*(display:\s*none|hidden)[^>]*>/gi) ?? []).length;
    evidence.push(
      makeEvidence("content", {
        source: "Static analysis of the returned markup",
        category: "content",
        signal: "Cloaking and redirect techniques",
        observation: `meta refresh=${metaRefresh}; hidden iframes=${hiddenIframes}`,
        result: metaRefresh || hiddenIframes ? "warning" : "pass",
        severity: metaRefresh || hiddenIframes ? "medium" : "none",
        confidence: 0.65,
        weight: metaRefresh || hiddenIframes ? -14 : 4,
        explanation:
          "Automatic refreshes and hidden frames are used to hide the real destination from analysis tools.",
      }),
    );

    return { status: "ok", detail: `${html.length} bytes analysed`, evidence };
  },
};
