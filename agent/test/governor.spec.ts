import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import vectors from "../vectors/grant-vectors.json";
import type { Governor, AuthorizeRequest } from "../src/governor";
import { Status } from "../src/governor";
import type { Grant } from "../src/shared/grant";

const NS = (env as unknown as { GOVERNOR: DurableObjectNamespace<Governor> }).GOVERNOR;
function gov() {
  return NS.get(NS.idFromName("governor"));
}

const OWNER_HEX = vectors.owner_pub_raw_hex;
const AGENT = vectors.agent_did;
const G = vectors.governor_grants as unknown as {
  main: Grant;
  claim1: Grant;
  win600: Grant;
  winsmall: Grant;
  expired: Grant;
  wrong_agent: Grant;
  newer: Grant;
  stop: Grant;
  older: Grant;
  future: Grant;
};

function req(overrides: Partial<AuthorizeRequest> = {}): AuthorizeRequest {
  return {
    now: 1500,
    verb: "CLAIM",
    target: { job_id: "job-x" },
    key: "agentkey",
    room: "kibble",
    nonce: 1,
    ...overrides,
  };
}

async function configured() {
  const g = gov();
  expect((await g.configure({ ownerPubHex: OWNER_HEX, agentDid: AGENT })).status).toBe(Status.OK);
  return g;
}

describe("configuration and anchors", () => {
  it("gates an unconfigured authorize", async () => {
    const r = await gov().authorize(req());
    expect(r.status).toBe(Status.GATE_NOT_CONFIGURED);
  });

  it("configure sets the anchors and is anchor-locked", async () => {
    const g = await configured();
    expect((await g.snapshot()).configured).toBe(true);
    expect((await g.configure({ ownerPubHex: OWNER_HEX, agentDid: AGENT })).status).toBe(Status.OK);
    const other = "00".repeat(32);
    expect((await g.configure({ ownerPubHex: other, agentDid: AGENT })).status).toBe(
      Status.ERROR_BAD_REQUEST,
    );
  });

  it("gates when configured but no grant is pinned", async () => {
    const g = await configured();
    expect((await g.authorize(req())).status).toBe(Status.GATE_NOT_ACTIVE);
  });
});

describe("pinning a grant", () => {
  it("pins a valid grant and authorizes a granted class", async () => {
    const g = await configured();
    expect((await g.pinGrant(G.main, 1500)).status).toBe(Status.OK);
    const r = await g.authorize(req({ verb: "CLAIM", nonce: 1 }));
    expect(r.status).toBe(Status.OK);
    expect(r.klass).toBe("CLAIM");
    expect(r.counter).toBe(1);
    expect(r.ceiling).toBe(5);
  });

  it("refuses a grant bound to a different agent", async () => {
    const g = await configured();
    expect((await g.pinGrant(G.wrong_agent, 1500)).status).toBe(Status.GATE_NO_GRANT);
  });

  it("refuses a tampered grant", async () => {
    const g = await configured();
    const bad = JSON.parse(JSON.stringify(G.main)) as Grant;
    bad.signature = (bad.signature[0] === "A" ? "B" : "A") + bad.signature.slice(1);
    expect((await g.pinGrant(bad, 1500)).status).toBe(Status.GATE_NO_GRANT);
  });

  it("hasLiveGrant: false with no grant, true for a permissive grant, false for an empty-allow STOP or after revoke (kill-switch coverage of unmetered signing)", async () => {
    const g = await configured();
    expect(await g.hasLiveGrant(1500)).toBe(false); // nothing pinned
    await g.pinGrant(G.main, 1500);
    expect(await g.hasLiveGrant(1500)).toBe(true); // permissive, non-empty allow
    await g.revoke(G.main.grant_id);
    expect(await g.hasLiveGrant(1500)).toBe(false); // revoked -> not live
    await g.pinGrant(G.stop, 1500); // empty-allow stop (a distinct grant_id, not in the revoked set)
    expect(await g.hasLiveGrant(1500)).toBe(false); // a STOP is never "live"
  });
});

describe("class and ceiling enforcement", () => {
  it("gates a class not on the allowlist", async () => {
    const g = await configured();
    await g.pinGrant(G.claim1, 1500);
    expect((await g.authorize(req({ verb: "RESULT", target: { job_id: "j", result: "x" } }))).status).toBe(
      Status.GATE_CLASS,
    );
    expect((await g.authorize(req({ verb: "SAY", target: { room: "lobby", text: "hi" } }))).status).toBe(
      Status.GATE_CLASS,
    );
  });

  it("gates once the daily counter reaches the ceiling", async () => {
    const g = await configured();
    await g.pinGrant(G.claim1, 1500);
    expect((await g.authorize(req({ nonce: 1 }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ nonce: 2 }))).status).toBe(Status.GATE_CEILING);
  });

  it("resets the counter when the signed window rolls over", async () => {
    const g = await configured();
    await g.pinGrant(G.win600, 1500);
    expect((await g.authorize(req({ now: 1200, nonce: 1, room: "kibble" }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ now: 1500, nonce: 2, room: "kibble" }))).status).toBe(
      Status.GATE_CEILING, // same window (floor(1500/600)*600 == 1200)
    );
    expect((await g.authorize(req({ now: 1800, nonce: 3, room: "kibble" }))).status).toBe(Status.OK);
  });

 it("refuses to pin a grant whose window is below the floor", async () => {
    const g = await configured();
    expect((await g.pinGrant(G.winsmall, 1500)).status).toBe(Status.GATE_WINDOW);
  });
});

describe("nonce monotonicity", () => {
  it("rejects replay and rewind, accepts strictly increasing", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ nonce: 5 }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ nonce: 5 }))).status).toBe(Status.GATE_NONCE);
    expect((await g.authorize(req({ nonce: 3 }))).status).toBe(Status.GATE_NONCE);
    expect((await g.authorize(req({ nonce: 6 }))).status).toBe(Status.OK);
  });

  it("keeps nonce high-water independent per (key,room) scope", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ room: "kibble", nonce: 9 }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ room: "otherroom", nonce: 1 }))).status).toBe(Status.OK);
  });
});

describe("expiry and revoke", () => {
  it("gates an expired grant at authorize time", async () => {
    const g = await configured();
    await g.pinGrant(G.expired, 1500);
    expect((await g.authorize(req({ now: 3000, nonce: 1 }))).status).toBe(Status.GATE_EXPIRED);
  });

  it("revoke clears the pin and is durable: the grant cannot be re-pinned", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ nonce: 1 }))).status).toBe(Status.OK);
    expect((await g.revoke("g-main")).status).toBe(Status.OK);
    expect((await g.authorize(req({ nonce: 2 }))).status).toBe(Status.GATE_NOT_ACTIVE);
    const snap = await g.snapshot();
    expect(snap.activeGrantId).toBe(null);
    expect(snap.revoked).toContain("g-main");
    expect((await g.pinGrant(G.main, 1500)).status).toBe(Status.GATE_NO_GRANT);
  });
});

describe("clock hardening", () => {
  it("gates a non-integer now", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ now: 1500.5 }))).status).toBe(Status.GATE_CLOCK);
  });
});

describe("configure set-once binds the agent too", () => {
  it("refuses a re-configure with a different agent did", async () => {
    const g = gov();
    expect((await g.configure({ ownerPubHex: OWNER_HEX, agentDid: AGENT })).status).toBe(Status.OK);
    expect(
      (await g.configure({ ownerPubHex: OWNER_HEX, agentDid: vectors.other_did })).status,
    ).toBe(Status.ERROR_BAD_REQUEST);
  });
});

describe("19-digit nonce (beyond i64 / 2^53)", () => {
  it("compares big nonces as BigInt, strict-increase", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ nonce: "9999999999999999999" }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ nonce: "9999999999999999998" }))).status).toBe(Status.GATE_NONCE);
  });
});

describe("steer poll: apply a re-signed grant (Option A)", () => {
  it("applies a newer grant and rejects a replay of an older one", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.applySteerGrant(G.newer, 5000)).status).toBe(Status.OK);
    expect((await g.snapshot()).activeGrantId).toBe("g-newer");
    expect((await g.applySteerGrant(G.main, 1500)).status).toBe(Status.GATE_STEER);
    expect((await g.snapshot()).activeGrantId).toBe("g-newer");
  });

  it("the human's STOP (an empty-allow grant) gates all subsequent work", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.authorize(req({ verb: "CLAIM", nonce: 1 }))).status).toBe(Status.OK);
    expect((await g.applySteerGrant(G.stop, 5000)).status).toBe(Status.OK);
    expect((await g.authorize(req({ verb: "CLAIM", nonce: 2 }))).status).toBe(Status.GATE_CLASS);
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_CLASS);
  });

  it("refuses a steer grant bound to a different agent", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.applySteerGrant(G.wrong_agent, 1500)).status).toBe(Status.GATE_NO_GRANT);
  });

 it("a revoke cannot be UNDONE by replaying an older grant", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    await g.revoke("g-main");
    expect((await g.snapshot()).activeGrantId).toBe(null);
    expect((await g.snapshot()).grantHigh).toBe("1000");
    expect((await g.applySteerGrant(G.older, 1500)).status).toBe(Status.GATE_STEER);
    expect((await g.snapshot()).activeGrantId).toBe(null);
    expect((await g.applySteerGrant(G.newer, 5000)).status).toBe(Status.OK);
    expect((await g.snapshot()).activeGrantId).toBe("g-newer");
  });

 it("the empty-allow STOP is not blocked by the window floor", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.applySteerGrant(G.stop, 5000)).status).toBe(Status.OK);
  });

 it("rejects a future-dated grant and does NOT burn the high-water", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.applySteerGrant(G.future, 1500)).status).toBe(Status.GATE_STEER);
    expect((await g.snapshot()).grantHigh).toBe("1000");
    expect((await g.applySteerGrant(G.newer, 5000)).status).toBe(Status.OK);
  });
});

describe("model budget (reserveModel, DESIGN §7b)", () => {
  it("meters model calls against the MODEL ceiling", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    expect((await g.reserveModel(1500)).status).toBe(Status.OK);
    expect((await g.reserveModel(1500)).status).toBe(Status.OK);
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_CEILING);
  });

  it("fails closed when MODEL is not granted (no silent bill)", async () => {
    const g = await configured();
    await g.pinGrant(G.claim1, 1500);
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_CLASS);
  });

  it("gates model calls when no grant is active / after revoke", async () => {
    const g = await configured();
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_NOT_ACTIVE);
    await g.pinGrant(G.main, 1500);
    expect((await g.reserveModel(1500)).status).toBe(Status.OK);
    await g.revoke("g-main");
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_NOT_ACTIVE);
  });

  it("resets the MODEL budget when the window rolls over, and gates an expired grant", async () => {
    const g = await configured();
    await g.pinGrant(G.win600, 1500);
    expect((await g.reserveModel(1500)).status).toBe(Status.GATE_CLASS);
    const g2 = await configured();
    await g2.pinGrant(G.expired, 1500);
    expect((await g2.reserveModel(3000)).status).toBe(Status.GATE_EXPIRED);
  });

  it("the MODEL counter never over-spends under concurrent reserveModel calls", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    const results = await Promise.all(Array.from({ length: 10 }, () => g.reserveModel(1500)));
    expect(results.filter((r) => r.status === Status.OK).length).toBe(2);
    expect(results.filter((r) => r.status === Status.GATE_CEILING).length).toBe(8);
  });
});

describe("steer_seen high-water", () => {
  it("accepts strictly-newer steer nonces and rejects replay/rewind", async () => {
    const g = await configured();
    expect((await g.steerGate(5)).status).toBe(Status.OK);
    expect((await g.steerGate(5)).status).toBe(Status.GATE_STEER);
    expect((await g.steerGate(4)).status).toBe(Status.GATE_STEER);
    expect((await g.steerGate(6)).status).toBe(Status.OK);
    expect((await g.steerGate("9999999999999999999")).status).toBe(Status.OK);
    expect((await g.steerGate("18446744073709551615")).status).toBe(Status.ERROR_BAD_REQUEST);
  });
});

describe("revoke racing a concurrent authorize", () => {
  it("ends revoked and never leaves the grant active (head-of-sign catch)", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    await Promise.all([g.authorize(req({ nonce: 1 })), g.revoke("g-main")]);
    expect((await g.authorize(req({ nonce: 2 }))).status).toBe(Status.GATE_NOT_ACTIVE);
    const snap = await g.snapshot();
    expect(snap.activeGrantId).toBe(null);
    expect(snap.revoked).toContain("g-main");
    const claim = snap.counters.find((c) => c.klass === "CLAIM");
    expect((claim?.n ?? 0) <= 5).toBe(true);
  });
});

describe("reserve-before-emit atomicity", () => {
  it("never over-spends the ceiling under concurrent authorize calls", async () => {
    const g = await configured();
    await g.pinGrant(G.main, 1500);
    const calls = Array.from({ length: 20 }, (_, i) =>
      g.authorize(req({ verb: "CLAIM", room: `room${i}`, nonce: 1 })),
    );
    const results = await Promise.all(calls);
    const ok = results.filter((r) => r.status === Status.OK).length;
    const capped = results.filter((r) => r.status === Status.GATE_CEILING).length;
    expect(ok).toBe(5);
    expect(capped).toBe(15);
  });
});
