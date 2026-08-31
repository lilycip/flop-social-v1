
export interface FetchGuardConfig {
  allowHosts: readonly string[];
  denyHosts?: readonly string[];
  maxBytes?: number;
}

export type GuardVerdict = { ok: true; url: URL } | { ok: false; reason: GuardReason };
export type GuardReason =
  | "EMPTY_ALLOWLIST"
  | "UNPARSEABLE"
  | "NOT_HTTPS"
  | "HAS_USERINFO"
  | "IP_LITERAL"
  | "BAD_PORT"
  | "DENYLISTED"
  | "OFF_ALLOWLIST";

const DEFAULT_MAX_BYTES = 1_000_000;

export function isIpLiteral(host: string): boolean {
  if (host.startsWith("[") && host.endsWith("]")) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

export function guardResearchUrl(raw: string, cfg: FetchGuardConfig): GuardVerdict {
  const allow = new Set((cfg.allowHosts ?? []).map((h) => h.toLowerCase()));
  const deny = new Set((cfg.denyHosts ?? []).map((h) => h.toLowerCase()));

  if (allow.size === 0) return { ok: false, reason: "EMPTY_ALLOWLIST" };

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "UNPARSEABLE" };
  }

  if (url.protocol !== "https:") return { ok: false, reason: "NOT_HTTPS" };
  if (url.username !== "" || url.password !== "") return { ok: false, reason: "HAS_USERINFO" };

  const host = url.hostname.toLowerCase();
  if (isIpLiteral(host)) return { ok: false, reason: "IP_LITERAL" };
  if (url.port !== "" && url.port !== "443") return { ok: false, reason: "BAD_PORT" };
  if (deny.has(host)) return { ok: false, reason: "DENYLISTED" };
  if (!allow.has(host)) return { ok: false, reason: "OFF_ALLOWLIST" };

  return { ok: true, url };
}

export const ResearchStatus = {
  OK: "OK",
  BLOCKED: "BLOCKED", // failed the guard (off-allowlist / non-https / ip / userinfo / port / deny)
  ERROR: "ERROR", // network / non-2xx / oversized / decode failure - never echoes the cause
} as const;
export type ResearchStatusValue = (typeof ResearchStatus)[keyof typeof ResearchStatus];

export type ResearchResult =
  | { status: "OK"; text: string; finalHost: string }
  | { status: "BLOCKED"; reason: GuardReason }
  | { status: "ERROR" };

export async function researchFetch(
  raw: string,
  cfg: FetchGuardConfig,
  fetchImpl: typeof fetch,
): Promise<ResearchResult> {
  const verdict = guardResearchUrl(raw, cfg);
  if (!verdict.ok) return { status: "BLOCKED", reason: verdict.reason };

  const maxBytes = cfg.maxBytes ?? DEFAULT_MAX_BYTES;
  try {
    const resp = await fetchImpl(verdict.url.toString(), {
      method: "GET",
      redirect: "manual", // never auto-follow a redirect off the allowlisted host
      headers: { accept: "text/html, text/plain, application/json;q=0.9, */*;q=0.1" },
    });
    if (resp.status < 200 || resp.status >= 300) return { status: "ERROR" };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > maxBytes) return { status: "ERROR" };
    const text = new TextDecoder("utf-8", { fatal: false, ignoreBOM: false }).decode(buf);
    return { status: "OK", text, finalHost: verdict.url.hostname.toLowerCase() };
  } catch {
    return { status: "ERROR" };
  }
}
