import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import gw from "../vectors/gateway-vectors.json";
import { Gateway } from "../src/index";
import type { Governor } from "../src/governor";
import type { Grant } from "../src/shared/grant";

const NS = (env as unknown as { GOVERNOR: DurableObjectNamespace<Governor> }).GOVERNOR;
const OWNER_DID = (gw.gw_grant as unknown as Grant).owner_did;

function makeGateway(envOver: Record<string, unknown> = {}): Gateway {
  const gEnv = {
    GOVERNOR: NS,
    KEY_SEED: gw.identity_seed_hex,
    OUR_DID: gw.our_did,
    OWNER_DID,
    ...envOver,
  };
  const ctxStub = { waitUntil() {}, passThroughOnException() {} };
  return new Gateway(ctxStub as unknown as ExecutionContext, gEnv as never);
}

describe("gateway self-configure on first boot", () => {
  it("configures a fresh Governor from env alone (no manual configure step)", async () => {
    const g = NS.get(NS.idFromName("governor"));
    expect((await g.snapshot()).configured).toBe(false);

    const gateway = makeGateway();
    const r = await gateway.sign({ shape: "note", value: "hello", nonce: 1 });
    expect(r.status).toBe("GATE_NOT_ACTIVE");

    const snap = await g.snapshot();
    expect(snap.configured).toBe(true);
  });

  it("is idempotent: repeated boots do not fail or re-anchor", async () => {
    const g = NS.get(NS.idFromName("governor"));
    await makeGateway().sign({ shape: "note", value: "x", nonce: 1 });
    await makeGateway().sign({ shape: "note", value: "y", nonce: 2 });
    const snap = await g.snapshot();
    expect(snap.configured).toBe(true);
  });

  it("FAILS SAFE with no OWNER_DID: the Governor stays unconfigured and gates everything", async () => {
    const g = NS.get(NS.idFromName("governor"));
    const gateway = makeGateway({ OWNER_DID: undefined });
    const r = await gateway.sign({ shape: "note", value: "x", nonce: 1 });
    expect(r.status).toBe("GATE_NOT_CONFIGURED");
    expect((await g.snapshot()).configured).toBe(false);
  });
});
