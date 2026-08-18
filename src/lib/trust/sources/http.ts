import { makeEvidence, type SourceAdapter } from "./base";

export const httpSource: SourceAdapter = {
  id: "http",
  label: "Live HTTP/TLS probe",
  async run(ctx) {
    const evidence = [];
    const { https, plain, url } = ctx;
    const probeSource = "Direct HTTP(S) request from NOVAIN infrastructure";

    if (!https.ok) {
      evidence.push(
        makeEvidence("http", {
          source: probeSource,
          category: "infrastructure",
          signal: "HTTPS reachability",
          observation: `Request to ${url} failed: ${https.error}`,
          result: "fail",
          severity: "high",
          confidence: 0.9,
          weight: -35,
          explanation:
            "The host could not be reached over HTTPS, so no live evidence about the service could be collected.",
        }),
      );
      return { status: "error", detail: https.error ?? "unreachable", evidence };
    }

    evidence.push(
      makeEvidence("http", {
        source: probeSource,
        category: "infrastructure",
        signal: "TLS handshake and HTTPS response",
        observation: `HTTPS request succeeded with status ${https.status} in ${https.elapsedMs}ms (final URL ${https.finalUrl})`,
        result: https.status && https.status < 400 ? "info" : "warning",
        confidence: 0.95,
        weight: https.status && https.status < 400 ? 0 : -8,
        explanation:
          "A valid certificate and a successful response prove the service is online and encrypted. This is a baseline fact, NOT evidence of trustworthiness — certificates are free and available to any actor.",
      }),
    );

    const hsts = https.headers["strict-transport-security"];
    evidence.push(
      makeEvidence("http", {
        source: "Response headers",
        category: "infrastructure",
        signal: "HTTP Strict Transport Security",
        observation: hsts ? `Strict-Transport-Security: ${hsts}` : "No Strict-Transport-Security header present",
        result: hsts ? "pass" : "warning",
        severity: hsts ? "none" : "low",
        confidence: 0.9,
        weight: hsts ? 6 : -4,
        explanation:
          "HSTS shows deliberate transport hardening; its absence is a weak negative signal, not proof of malice.",
      }),
    );

    const csp = https.headers["content-security-policy"];
    const xfo = https.headers["x-frame-options"];
    const xcto = https.headers["x-content-type-options"];
    const present = [csp && "content-security-policy", xfo && "x-frame-options", xcto && "x-content-type-options"].filter(Boolean);
    evidence.push(
      makeEvidence("http", {
        source: "Response headers",
        category: "infrastructure",
        signal: "Security response headers",
        observation: `Present: ${present.join(", ") || "none"}`,
        result: present.length >= 2 ? "pass" : "warning",
        severity: present.length === 0 ? "low" : "none",
        confidence: 0.85,
        weight: present.length >= 2 ? 8 : present.length === 1 ? 2 : -6,
        explanation: "Security headers indicate an operator that invests in application hardening.",
      }),
    );

    if (plain.ok) {
      const upgraded = plain.finalUrl.startsWith("https://");
      evidence.push(
        makeEvidence("http", {
          source: probeSource,
          category: "infrastructure",
          signal: "Plain HTTP to HTTPS upgrade",
          observation: `http://${ctx.hostname} resolved to ${plain.finalUrl}`,
          result: upgraded ? "pass" : "fail",
          severity: upgraded ? "none" : "medium",
          confidence: 0.9,
          weight: upgraded ? 6 : -14,
          explanation:
            "Serving plaintext HTTP without redirecting exposes users to interception and credential theft.",
        }),
      );
    } else {
      evidence.push(
        makeEvidence("http", {
          source: probeSource,
          category: "infrastructure",
          signal: "Plain HTTP to HTTPS upgrade",
          observation: `HTTP probe unavailable: ${plain.error}`,
          result: "unknown",
          confidence: 0,
          explanation: "The plaintext probe could not be completed, so no conclusion is drawn.",
        }),
      );
    }

    return { status: "ok", detail: `HTTP ${https.status}`, evidence };
  },
};
