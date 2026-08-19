/* Low-level probes. Evidence records are built by the source adapters. */


export interface FetchResult {
  ok: boolean;
  finalUrl: string;
  status: number | null;
  headers: Record<string, string>;
  html: string;
  error: string | null;
  redirected: boolean;
  elapsedMs: number;
}

const UA = "NOVAIN-TRUST-Verifier/1.0 (+evidence-collection)";

export async function fetchSite(url: string, timeoutMs = 12000): Promise<FetchResult> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": UA, accept: "text/html,*/*" },
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    let html = "";
    try {
      html = (await res.text()).slice(0, 400_000);
    } catch {
      html = "";
    }
    return {
      ok: true,
      finalUrl: res.url || url,
      status: res.status,
      headers,
      html,
      error: null,
      redirected: (res.url || url) !== url,
      elapsedMs: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      finalUrl: url,
      status: null,
      headers: {},
      html: "",
      error: err instanceof Error ? err.message : String(err),
      redirected: false,
      elapsedMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Public RDAP bootstrap lookup. Returns null when the source is unavailable. */
export async function fetchRdap(
  domain: string,
  timeoutMs = 9000,
): Promise<{ ok: boolean; data: unknown; source: string; error: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { accept: "application/rdap+json", "user-agent": UA },
    });
    if (!res.ok) {
      return { ok: false, data: null, source: "rdap.org", error: `HTTP ${res.status}` };
    }
    return { ok: true, data: await res.json(), source: "rdap.org", error: null };
  } catch (err) {
    return {
      ok: false,
      data: null,
      source: "rdap.org",
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

export interface RdapFacts {
  registered: boolean;
  registrationDate: string | null;
  expirationDate: string | null;
  registrar: string | null;
  statuses: string[];
  ageDays: number | null;
}

export function parseRdap(data: unknown): RdapFacts | null {
  if (!data || typeof data !== "object") return null;
  const obj = data as Record<string, unknown>;
  const events = Array.isArray(obj["events"]) ? (obj["events"] as Record<string, unknown>[]) : [];
  const find = (name: string) =>
    events.find((e) => String(e["eventAction"] ?? "").toLowerCase() === name)?.["eventDate"];
  const registration = find("registration") ?? find("last changed") ?? null;
  const expiration = find("expiration") ?? null;
  const entities = Array.isArray(obj["entities"])
    ? (obj["entities"] as Record<string, unknown>[])
    : [];
  const registrarEntity = entities.find((e) =>
    (Array.isArray(e["roles"]) ? (e["roles"] as string[]) : []).includes("registrar"),
  );
  let registrar: string | null = null;
  const vcard = registrarEntity?.["vcardArray"];
  if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
    for (const entry of vcard[1] as unknown[]) {
      if (Array.isArray(entry) && entry[0] === "fn") registrar = String(entry[3]);
    }
  }
  const regDate = registration ? String(registration) : null;
  const ageDays = regDate
    ? Math.floor((Date.now() - new Date(regDate).getTime()) / 86_400_000)
    : null;
  return {
    registered: true,
    registrationDate: regDate,
    expirationDate: expiration ? String(expiration) : null,
    registrar,
    statuses: Array.isArray(obj["status"]) ? (obj["status"] as string[]).map(String) : [],
    ageDays: Number.isFinite(ageDays) ? ageDays : null,
  };
}
