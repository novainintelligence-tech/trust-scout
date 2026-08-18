import { createFileRoute } from "@tanstack/react-router";
import { MODEL_VERSION } from "@/lib/trust/engine";

export const Route = createFileRoute("/api/public/v1/health")({
  server: {
    handlers: {
      GET: async () =>
        new Response(
          JSON.stringify({
            status: "ok",
            service: "novain-trust",
            model_version: MODEL_VERSION,
            checked_at: new Date().toISOString(),
          }),
          { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } },
        ),
    },
  },
});
