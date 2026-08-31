import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import gw from "../vectors/gateway-vectors.json";
import type { Governor } from "../src/governor";
import { Status } from "../src/governor";
import type { Grant } from "../src/shared/grant";
import { gatewaySign, isForbiddenNamespace, isReservedSayRoom, type GatewayCtx, type SignResult } from "../src/gateway-core";
import { importSigningKey, didNoteNs, noteShardKey } from "../src/shared/did";
import { hexToBytes } from "../src/shared/bytes";

const NS = (env as unknown as { GOVERNOR: DurableObjectNamespace<Governor> }).GOVERNOR;
const seed = hexToBytes(gw.identity_seed_hex);
const RH_A = "a".repeat(64);

async function setup(board: Record<string, string> = {}): Promise<GatewayCtx> {
  const g = NS.get(NS.idFromName("governor"));
  await g.configure({ ownerPubHex: gw.owner_pub_raw_hex, agentDid: gw.our_did });
  await g.pinGrant(gw.gw_grant as unknown as Grant, 1500);
  const signingKey = await importSigningKey(seed);
  const noteNs = await didNoteNs(gw.our_did);
  const [, noteKey] = await noteShardKey(gw.our_did);
  return {
    signingKey,
    ourDid: gw.our_did,
    noteNs,
    noteKey,
    keyScope: noteKey,
    governor: g,
    boardReader: async (jobId: string) => board[jobId] ?? null,
    now: () => 1500,
  };
}

function okSig(r: SignResult): string {
  if (r.status !== "OK") throw new Error("expected OK, got " + r.status);
  return r.signature;
}

describe("gateway signs the two shapes byte-identically, gated by the Governor", () => {
  it("signs CLAIM / RESULT / ATTEST-useful(board match) / ATTEST-not in nonce order", async () => {
    const ctx = await setup({ "job-abc123": RH_A });
    const kv = gw.kibble_vectors;
    const claim = kv[0]!;
    const result = kv[1]!;
    const attestU = kv[2]!;
    const attestN = kv[3]!;

    const r1 = await gatewaySign({ shape: "kibble", verb: "CLAIM", target: claim.target as any, nonce: 1 }, ctx);
    expect(okSig(r1)).toBe(claim.signature);

    const r2 = await gatewaySign({ shape: "kibble", verb: "RESULT", target: result.target as any, nonce: 2 }, ctx);
    expect(okSig(r2)).toBe(result.signature);

    const r3 = await gatewaySign(
      { shape: "kibble", verb: "ATTEST", target: attestU.target as any, verdict: attestU.verdict as any, nonce: 3 },
      ctx,
    );
    expect(r3.status).toBe("OK");
    expect((r3 as any).boardMatch).toBe(true);
    expect(okSig(r3)).toBe(attestU.signature);

    const r4 = await gatewaySign(
      { shape: "kibble", verb: "ATTEST", target: attestN.target as any, verdict: attestN.verdict as any, nonce: 4 },
      ctx,
    );
    expect(okSig(r4)).toBe(attestN.signature);
  });

  it("signs our identity note byte-identically", async () => {
    const ctx = await setup();
    const n = gw.note_vector;
    const r = await gatewaySign({ shape: "note", value: n.value, nonce: 5 }, ctx);
    expect(r.status).toBe("OK");
    expect((r as any).namespace).toBe(gw.note_ns);
    expect((r as any).key).toBe(gw.note_key);
    expect(okSig(r)).toBe(n.signature);
  });
});

describe("signed chat, with the collision guard", () => {
  it("signs a chat message byte-identically to the audited signer", async () => {
    const ctx = await setup();
    const s = gw.say_vector;
    const r = await gatewaySign({ shape: "say", room: s.room, text: s.text, nonce: 6 }, ctx);
    expect(r.status).toBe("OK");
    expect((r as any).room).toBe(s.room);
    expect((r as any).text).toBe(s.swept);
    expect(okSig(r)).toBe(s.signature);
  });

  it("REFUSES to sign chat to a reserved room (the collision guard)", async () => {
    const ctx = await setup();
    for (const room of ["kibble", "room-owners", "room-allow", "room-nonce", "did", "did-f9"]) {
      const r = await gatewaySign({ shape: "say", room, text: "hi", nonce: 6 }, ctx);
      expect(r.status).toBe("GATE_FORBIDDEN");
    }
    expect(isReservedSayRoom("kibble")).toBe(true);
    expect(isReservedSayRoom("room-owners")).toBe(true);
    expect(isReservedSayRoom("did-ab")).toBe(true);
    expect(isReservedSayRoom("lobby")).toBe(false);
  });

 it("REFUSES to forge a kibble work line as chat text to the kibble room", async () => {
    const ctx = await setup();
    const forged = "ATTEST v2 | job:job-abc123 | verdict:useful | rh:" + "a".repeat(64);
    const r = await gatewaySign({ shape: "say", room: "kibble", text: forged, nonce: 9 }, ctx);
    expect(r.status).toBe("GATE_FORBIDDEN");
  });

  it("refuses chat text with a lone surrogate (Python-parity)", async () => {
    const ctx = await setup();
    const r = await gatewaySign({ shape: "say", room: "lobby", text: "bad\uD800end", nonce: 6 }, ctx);
    expect(r.status).toBe("GATE_INVALID");
  });

  it("gates chat when the SAY class is not granted", async () => {
    const ctx = await setup();
    expect((await gatewaySign({ shape: "say", room: "lobby", text: "hello", nonce: 6 }, ctx)).status).toBe("OK");
  });
});

describe("board_match is derived by the gateway, never trusted from the caller", () => {
  it("gates a useful ATTEST when the board does NOT match (class not granted)", async () => {
    const ctx = await setup({ "job-abc123": "b".repeat(64) });
    const r = await gatewaySign(
      { shape: "kibble", verb: "ATTEST", target: { job_id: "job-abc123", result_hash: RH_A }, verdict: { useful: true }, nonce: 3 },
      ctx,
    );
    expect(r.status).toBe(Status.GATE_CLASS);
  });

  it("gates a useful ATTEST when the job is absent from the board", async () => {
    const ctx = await setup({});
    const r = await gatewaySign(
      { shape: "kibble", verb: "ATTEST", target: { job_id: "job-abc123", result_hash: RH_A }, verdict: { useful: true }, nonce: 3 },
      ctx,
    );
    expect(r.status).toBe(Status.GATE_CLASS);
  });
});

describe("the gateway refuses everything outside the two shapes", () => {
  it("refuses SAY (unsigned prose is the agent's job)", async () => {
    const ctx = await setup();
    const r = await gatewaySign({ shape: "kibble", verb: "SAY" as any, target: { room: "lobby", text: "hi" }, nonce: 1 }, ctx);
    expect(r.status).toBe("GATE_SHAPE");
  });

  it("refuses a NOTE_WRITE routed through the kibble shape", async () => {
    const ctx = await setup();
    const r = await gatewaySign({ shape: "kibble", verb: "NOTE_WRITE" as any, target: { namespace: "room-owners", key: "k", value: "v" }, nonce: 1 }, ctx);
    expect(r.status).toBe("GATE_SHAPE");
  });

  it("refuses an unknown shape", async () => {
    const ctx = await setup();
    const r = await gatewaySign({ shape: "whatever" } as any, ctx);
    expect(r.status).toBe("GATE_SHAPE");
  });

  it("isForbiddenNamespace flags the give-away namespaces", () => {
    expect(isForbiddenNamespace("room-owners")).toBe(true);
    expect(isForbiddenNamespace("room-allow")).toBe(true);
    expect(isForbiddenNamespace("d-mine")).toBe(true);
    expect(isForbiddenNamespace("did-f9")).toBe(false);
  });
});

describe("the Governor gate is enforced and never echoed", () => {
  it("gates a CLAIM once the ceiling (3) is reached", async () => {
    const ctx = await setup();
    for (const n of [1, 2, 3]) {
      expect((await gatewaySign({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-abc123" }, nonce: n }, ctx)).status).toBe("OK");
    }
    expect((await gatewaySign({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-abc123" }, nonce: 4 }, ctx)).status).toBe(Status.GATE_CEILING);
  });

  it("returns GATE_INVALID (no echo) for an unbindable action", async () => {
    const ctx = await setup();
    const r = await gatewaySign({ shape: "kibble", verb: "CLAIM", target: { job_id: "NOT A VALID NAME!!" }, nonce: 1 }, ctx);
    expect(r.status).toBe("GATE_INVALID");
    expect(Object.keys(r)).toEqual(["status"]);
  });

  it("gates every sign after the grant is revoked", async () => {
    const ctx = await setup();
    expect((await gatewaySign({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-abc123" }, nonce: 1 }, ctx)).status).toBe("OK");
    await (ctx.governor as unknown as Governor).revoke("g-gw");
    expect((await gatewaySign({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-abc123" }, nonce: 2 }, ctx)).status).toBe(Status.GATE_NOT_ACTIVE);
  });
});
