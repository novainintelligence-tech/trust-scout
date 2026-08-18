import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { verifyWebsite, normalizeTarget } from "@/lib/trust/engine";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, authorization",
  "Content-Type": "application/json",
};

const bodySchema = z.object({
  url: z.string().trim().min(3).max(2048).optional(),
  target: z.string().trim().min(3).max(2048).optional(),
});

export const Route = createFileRoute("/api/public/v1/verify/website")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: cors }),
      POST: async ({ request }) => {
        let parsed: z.infer<typeof bodySchema>;
        try {
          parsed = bodySchema.parse(await request.json());
        } catch {
          return new Response(
            JSON.stringify({ error: "invalid_request", message: "Provide a JSON body with a `url` field." }),
            { status: 400, headers: cors },
          );
        }

        const raw = parsed.url ?? parsed.target ?? "";
        const normalized = normalizeTarget(raw);
        if (!normalized) {
          return new Response(
            JSON.stringify({ error: "invalid_target", message: "Could not parse a hostname from the supplied value." }),
            { status: 400, headers: cors },
          );
        }

        let report;
        try {
          report = await verifyWebsite(raw);
        } catch (err) {
          return new Response(
            JSON.stringify({
              error: "verification_failed",
              message: err instanceof Error ? err.message : "Unknown error",
            }),
            { status: 502, headers: cors },
          );
        }

        // Persist the report so the verificationId can be resolved later.
        let persisted = false;
        try {
          const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
          const { error } = await supabaseAdmin.from("verifications").insert({
            id: report.verification_id,
            target: report.target,
            domain: report.domain,
            trust_score: report.trust_score,
            risk_level: report.risk_level,
            status: report.status,
            confidence: report.confidence,
            capped: report.capped,
            cap_reasons: JSON.parse(JSON.stringify(report.applied_gates)),
            categories: JSON.parse(JSON.stringify(report.categories)),
            evidence: JSON.parse(JSON.stringify(report.evidence)),
            recommendation: report.recommendation,
            duration_ms: report.duration_ms,
          });
          persisted = !error;
          if (error) console.error("verification persistence failed", error.message);
        } catch (err) {
          console.error("verification persistence failed", err);
        }

        return new Response(JSON.stringify({ ...report, persisted }), { status: 200, headers: cors });
      },
    },
  },
});
