import { makeEvidence, resolveDns, type SourceAdapter } from "./base";

const SRC = "Google Public DNS (DNS-over-HTTPS, dns.google)";

export const dnsSource: SourceAdapter = {
  id: "dns",
  label: "DNS records (DoH)",
  async run(ctx) {
    const evidence = [];
    const [a, mx, ns, txt, dmarc, caa] = await Promise.all([
      resolveDns(ctx.domain, "A"),
      resolveDns(ctx.domain, "MX"),
      resolveDns(ctx.domain, "NS"),
      resolveDns(ctx.domain, "TXT"),
      resolveDns(`_dmarc.${ctx.domain}`, "TXT"),
      resolveDns(ctx.domain, "CAA"),
    ]);

    if (!a.ok || !a.data) {
      evidence.push(
        makeEvidence("dns", {
          source: SRC,
          category: "infrastructure",
          signal: "Authoritative DNS resolution",
          observation: `DNS lookup unavailable: ${a.error ?? "no response"}`,
          result: "unknown",
          confidence: 0,
          explanation: "DNS could not be queried, so hosting facts remain UNKNOWN.",
        }),
      );
      return { status: "unavailable", detail: a.error ?? "DNS unavailable", evidence };
    }

    const addresses = (a.data.Answer ?? []).filter((r) => r.type === 1).map((r) => r.data);
    evidence.push(
      makeEvidence("dns", {
        source: SRC,
        category: "infrastructure",
        signal: "Authoritative DNS resolution",
        observation: addresses.length
          ? `A records: ${addresses.slice(0, 4).join(", ")}`
          : `No A record returned (DNS status ${a.data.Status})`,
        result: addresses.length ? "pass" : "fail",
        severity: addresses.length ? "none" : "medium",
        confidence: 0.9,
        weight: addresses.length ? 4 : -20,
        explanation:
          "A resolvable hostname is a baseline fact; a domain that does not resolve cannot be operating a real service.",
      }),
    );

    const nsRecords = (ns.data?.Answer ?? []).filter((r) => r.type === 2).map((r) => r.data);
    evidence.push(
      nsRecords.length
        ? makeEvidence("dns", {
            source: SRC,
            category: "infrastructure",
            signal: "Nameserver delegation",
            observation: `NS: ${nsRecords.slice(0, 4).join(", ")}`,
            result: "info",
            confidence: 0.85,
            weight: nsRecords.length >= 2 ? 3 : 0,
            explanation:
              "Redundant nameserver delegation indicates managed hosting rather than throwaway infrastructure.",
          })
        : makeEvidence("dns", {
            source: SRC,
            category: "infrastructure",
            signal: "Nameserver delegation",
            observation: "No NS records returned",
            result: "unknown",
            confidence: 0,
            explanation: "Delegation data is UNKNOWN; no conclusion drawn.",
          }),
    );

    const mxRecords = (mx.data?.Answer ?? []).filter((r) => r.type === 15).map((r) => r.data);
    evidence.push(
      makeEvidence("dns", {
        source: SRC,
        category: "identity",
        signal: "Mail exchange configuration",
        observation: mxRecords.length
          ? `MX: ${mxRecords.slice(0, 3).join(", ")}`
          : "No MX records — the domain cannot receive email",
        result: mxRecords.length ? "pass" : "warning",
        severity: mxRecords.length ? "none" : "low",
        confidence: 0.8,
        weight: mxRecords.length ? 8 : -8,
        explanation:
          "An operator that can receive mail on its own domain is contactable and accountable; disposable scam domains frequently have none.",
      }),
    );

    const txtRecords = (txt.data?.Answer ?? []).map((r) => r.data.replace(/"/g, ""));
    const spf = txtRecords.find((t) => t.toLowerCase().startsWith("v=spf1"));
    const dmarcRecord = (dmarc.data?.Answer ?? [])
      .map((r) => r.data.replace(/"/g, ""))
      .find((t) => t.toLowerCase().startsWith("v=dmarc1"));
    const emailAuth = [spf && "SPF", dmarcRecord && "DMARC"].filter(Boolean);
    evidence.push(
      makeEvidence("dns", {
        source: SRC,
        category: "infrastructure",
        signal: "Email authentication policy (SPF/DMARC)",
        observation: emailAuth.length
          ? `${emailAuth.join(" + ")} published${dmarcRecord ? `; DMARC: ${dmarcRecord.slice(0, 90)}` : ""}`
          : "Neither SPF nor DMARC published",
        result: emailAuth.length === 2 ? "pass" : emailAuth.length ? "warning" : "warning",
        severity: emailAuth.length ? "none" : "low",
        confidence: 0.8,
        weight: emailAuth.length === 2 ? 8 : emailAuth.length ? 3 : -6,
        explanation:
          "SPF and DMARC show deliberate anti-spoofing configuration by an operator that cares about its domain being abused.",
      }),
    );

    const caaRecords = (caa.data?.Answer ?? []).filter((r) => r.type === 257);
    evidence.push(
      makeEvidence("dns", {
        source: SRC,
        category: "infrastructure",
        signal: "Certificate Authority Authorization (CAA)",
        observation: caaRecords.length ? `${caaRecords.length} CAA record(s) published` : "No CAA records published",
        result: caaRecords.length ? "pass" : "info",
        confidence: 0.7,
        weight: caaRecords.length ? 5 : 0,
        explanation:
          "CAA restricts which authorities may issue certificates for the domain — a mature hardening practice. Its absence is common and not penalised.",
      }),
    );

    return { status: "ok", detail: `Resolved ${addresses.length} A record(s)`, evidence };
  },
};
