import { createFileRoute } from "@tanstack/react-router";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" };

export const Route = createFileRoute("/api/public/v1/verifications/$id")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const id = params.id;
        if (!/^[0-9a-f-]{36}$/i.test(id)) {
          return new Response(JSON.stringify({ error: "invalid_id" }), { status: 400, headers });
        }
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data, error } = await supabaseAdmin
          .from("verifications")
          .select("*")
          .eq("id", id)
          .maybeSingle();
        if (error) {
          return new Response(JSON.stringify({ error: "lookup_failed" }), { status: 500, headers });
        }
        if (!data) {
          return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers });
        }
        return new Response(JSON.stringify(data), { headers });
      },
    },
  },
});
