import { describe, it, expect } from "vitest";
import { guardResearchUrl, researchFetch, type FetchGuardConfig } from "../src/agent-fetch";

const ALLOW: FetchGuardConfig = { allowHosts: ["example.com", "api.github.com"] };

describe("guardResearchUrl - deny-by-default", () => {
  it("denies everything when the allowlist is empty", () => {
    const v = guardResearchUrl("https://example.com/x", { allowHosts: [] });
    expect(v).toEqual({ ok: false, reason: "EMPTY_ALLOWLIST" });
  });

  it("allows an exact allowlisted https host on the default port", () => {
    const v = guardResearchUrl("https://example.com/path?q=1", ALLOW);
    expect(v.ok).toBe(true);
  });

  it("rejects each unsafe shape with its specific reason", () => {
    const cases: Array<[string, string]> = [
      ["notaurl", "UNPARSEABLE"],
      ["http://example.com", "NOT_HTTPS"],
      ["ftp://example.com", "NOT_HTTPS"],
      ["https://user:pass@example.com", "HAS_USERINFO"],
      ["https://127.0.0.1/x", "IP_LITERAL"],
      ["https://169.254.169.254/latest/meta-data", "IP_LITERAL"], // cloud metadata SSRF
      ["https://[::1]/x", "IP_LITERAL"],
      ["https://example.com:8080/x", "BAD_PORT"],
      ["https://evil.com/x", "OFF_ALLOWLIST"],
    ];
    for (const [url, reason] of cases) {
      const v = guardResearchUrl(url, ALLOW);
      expect(v.ok, `${url} should be blocked`).toBe(false);
      if (!v.ok) expect(v.reason, url).toBe(reason);
    }
  });

  it("explicit :443 is accepted (it is the default port)", () => {
    expect(guardResearchUrl("https://example.com:443/x", ALLOW).ok).toBe(true);
  });

  it("force-denies a denylisted host even if it is also on the allowlist", () => {
    const cfg: FetchGuardConfig = { allowHosts: ["chat.technocore.example"], denyHosts: ["chat.technocore.example"] };
    const v = guardResearchUrl("https://chat.technocore.example/kv/room/x/set", cfg);
    expect(v).toEqual({ ok: false, reason: "DENYLISTED" });
  });

  it("matches the host case-insensitively", () => {
    expect(guardResearchUrl("https://EXAMPLE.com/x", ALLOW).ok).toBe(true);
  });
});

describe("researchFetch - a blocked URL never touches the network", () => {
  it("returns BLOCKED and does not call fetch", async () => {
    let called = 0;
    const fake = (async () => {
      called++;
      return new Response("x", { status: 200 });
    }) as unknown as typeof fetch;
    const r = await researchFetch("https://evil.com/x", ALLOW, fake);
    expect(r).toEqual({ status: "BLOCKED", reason: "OFF_ALLOWLIST" });
    expect(called).toBe(0);
  });

  it("returns OK text for an allowlisted 200", async () => {
    const fake = (async () => new Response("hello", { status: 200 })) as unknown as typeof fetch;
    const r = await researchFetch("https://example.com/x", ALLOW, fake);
    expect(r).toEqual({ status: "OK", text: "hello", finalHost: "example.com" });
  });

  it("treats a redirect as ERROR (the target is unguarded)", async () => {
    const fake = (async () => new Response("", { status: 301, headers: { location: "https://evil.com" } })) as unknown as typeof fetch;
    const r = await researchFetch("https://example.com/x", ALLOW, fake);
    expect(r).toEqual({ status: "ERROR" });
  });

  it("maps a non-2xx and a thrown fetch to a bare ERROR (never echoes the cause)", async () => {
    const f404 = (async () => new Response("secret-body", { status: 404 })) as unknown as typeof fetch;
    expect(await researchFetch("https://example.com/x", ALLOW, f404)).toEqual({ status: "ERROR" });
    const fThrow = (async () => {
      throw new Error("with a stack");
    }) as unknown as typeof fetch;
    expect(await researchFetch("https://example.com/x", ALLOW, fThrow)).toEqual({ status: "ERROR" });
  });

  it("bounds the body: an oversized response is ERROR", async () => {
    const big = "x".repeat(50);
    const fake = (async () => new Response(big, { status: 200 })) as unknown as typeof fetch;
    const r = await researchFetch("https://example.com/x", { allowHosts: ["example.com"], maxBytes: 10 }, fake);
    expect(r).toEqual({ status: "ERROR" });
  });
});
