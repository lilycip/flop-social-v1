import { describe, it, expect, vi } from "vitest";
import { pollSteer } from "../src/steer-poll";
import type { Grant } from "../src/shared/grant";

function grant(id: string, issued: number | string, valid = true): Grant {
  return {
    grant_id: id, owner_did: "did:key:zOwner", agent_did: "did:key:zAgent",
    issued, expiry: 9e9, window: 86400, allow: {}, signature: valid ? "sig" : "BAD",
  } as unknown as Grant;
}

describe("pollSteer applies the single newest valid grant", () => {
  it("stops after the newest valid grant (never verifies past it)", async () => {
    const apply = vi.fn(async (g: Grant) => ({ status: g.signature === "BAD" ? "GATE_NO_GRANT" : "OK" }));
    const r = await pollSteer({
      readGrants: async () => [grant("g-old", 1000), grant("g-new", 2000)],
      applyGrant: apply,
      now: () => 1500,
    });
    expect(r.applied).toBe(1);
    expect(apply).toHaveBeenCalledTimes(1);
    expect((apply.mock.calls[0]![0] as Grant).grant_id).toBe("g-new");
  });

  it("falls through a newest-but-INVALID grant to the next valid one", async () => {
    const apply = vi.fn(async (g: Grant) => ({ status: g.signature === "BAD" ? "GATE_NO_GRANT" : "OK" }));
    const r = await pollSteer({
      readGrants: async () => [grant("g-bad", 3000, false), grant("g-ok", 2000)],
      applyGrant: apply,
      now: () => 1500,
    });
    expect(r.applied).toBe(1);
    expect(r.rejected).toBe(1);
    expect((apply.mock.calls[1]![0] as Grant).grant_id).toBe("g-ok");
  });

 it("bounds the per-tick work under a flood", async () => {
    const apply = vi.fn(async (_g: Grant) => ({ status: "GATE_NO_GRANT" }));
    const flood = Array.from({ length: 500 }, (_, i) => grant("g-" + i, 1000 + i, false));
    const r = await pollSteer({ readGrants: async () => flood, applyGrant: apply, now: () => 1500 });
    expect(apply.mock.calls.length).toBeLessThanOrEqual(64);
    expect(r.applied).toBe(0);
  });

 it("orders by BigInt issued, so a 19-digit newest wins", async () => {
    const apply = vi.fn(async (_g: Grant) => ({ status: "OK" }));
    await pollSteer({
      readGrants: async () => [grant("g-a", "9999999999999999998"), grant("g-b", "9999999999999999999")],
      applyGrant: apply,
      now: () => 1500,
    });
    expect((apply.mock.calls[0]![0] as Grant).grant_id).toBe("g-b");
  });

  it("dedups by grant_id", async () => {
    const apply = vi.fn(async (_g: Grant) => ({ status: "GATE_NO_GRANT" }));
    await pollSteer({
      readGrants: async () => [grant("g-dup", 1000), grant("g-dup", 1000), grant("g-dup", 1000)],
      applyGrant: apply,
      now: () => 1500,
    });
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it("ignores malformed candidates without crashing", async () => {
    const apply = vi.fn(async (_g: Grant) => ({ status: "OK" }));
    const r = await pollSteer({
      readGrants: async () => [null, { grant_id: 123 }, "nope", grant("g-ok", 5000)],
      applyGrant: apply,
      now: () => 1500,
    });
    expect(r.applied).toBe(1);
    expect((apply.mock.calls[0]![0] as Grant).grant_id).toBe("g-ok");
  });

  it("returns a clean zero when the reader throws or returns a non-array", async () => {
    const apply = async () => ({ status: "OK" });
    expect(await pollSteer({ readGrants: async () => { throw new Error("io"); }, applyGrant: apply, now: () => 1 })).toEqual({ applied: 0, rejected: 0 });
    expect(await pollSteer({ readGrants: async () => ({}) as unknown as unknown[], applyGrant: apply, now: () => 1 })).toEqual({ applied: 0, rejected: 0 });
  });

  it("counts an applyGrant throw as a rejection, not a crash", async () => {
    const r = await pollSteer({
      readGrants: async () => [grant("g-x", 1000)],
      applyGrant: async () => { throw new Error("boom"); },
      now: () => 1500,
    });
    expect(r).toEqual({ applied: 0, rejected: 1 });
  });
});
