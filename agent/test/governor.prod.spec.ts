import { describe, it, expect } from "vitest";
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
const G = vectors.governor_grants as unknown as { prod: Grant };

function req(overrides: Partial<AuthorizeRequest> = {}): AuthorizeRequest {
  return { now: 0, verb: "CLAIM", target: { job_id: "job-x" }, key: "agentkey", room: "kibble", nonce: 1, ...overrides };
}

describe("production clock", () => {
  it("ignores the caller `now`: two wildly different clocks share one real window", async () => {
    const g = gov();
    expect((await g.configure({ ownerPubHex: OWNER_HEX, agentDid: AGENT })).status).toBe(Status.OK);
    expect((await g.pinGrant(G.prod, 0)).status).toBe(Status.OK);
    expect((await g.authorize(req({ now: 0, nonce: 1 }))).status).toBe(Status.OK);
    expect((await g.authorize(req({ now: 2000000000, nonce: 2 }))).status).toBe(Status.GATE_CEILING);
  });

  it("still rejects a malformed caller now in production", async () => {
    const g = gov();
    await g.configure({ ownerPubHex: OWNER_HEX, agentDid: AGENT });
    await g.pinGrant(G.prod, 0);
    expect((await g.authorize(req({ now: 1.5, nonce: 1 }))).status).toBe(Status.GATE_CLOCK);
  });
});
