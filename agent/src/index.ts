import { WorkerEntrypoint } from "cloudflare:workers";
import { gatewaySign, type GatewayCtx, type SignRequest, type SignResult } from "./gateway-core";
import { modelComplete, type ModelResult } from "./model-proxy";
import { pollSteer } from "./steer-poll";
import { readNote, readJobResultHash } from "./protocol-read";
import type { Governor } from "./governor";
import type { Grant } from "./shared/grant";
import { bytesToHex, hexToBytes, sha256Hex, utf8 } from "./shared/bytes";
import { canonInt } from "./shared/canon";
import { noteSigInput, singleLine, urlNoteSet } from "./shared/protocol";
import {
  didNoteNs,
  importSigningKey,
  noteShardKey,
  pubRawFromDid,
  signB64url,
  verifyB64url,
} from "./shared/did";

export { Governor } from "./governor";

interface Env {
  GOVERNOR: DurableObjectNamespace<Governor>;
  KEY_SEED?: string;
  OUR_DID?: string;
  AI?: Ai;
  MODEL_NAME?: string;
  OWNER_DID?: string;
  // Names the private task slot so the owner's tasks are not discoverable on the public board. NOT an encryption key.
  TASK_SECRET?: string;
}

const GOVERNOR_NAME = "governor";
const BOOT_PROBE = utf8("flop-gateway-boot-probe");

export async function readOwnerGrant(fetchImpl: typeof fetch, ownerDid: string): Promise<unknown[]> {
  const ns = await didNoteNs(ownerDid);
  const [, shardKey] = await noteShardKey(ownerDid);
  const value = await readNote(fetchImpl, ns, shardKey + "-grant");
  if (value === null) return [];
  try {
    const g: unknown = JSON.parse(value);
    return g !== null && typeof g === "object" && !Array.isArray(g) ? [g] : [];
  } catch {
    return [];
  }
}

const MAX_TASKS = 8;
const MAX_TASK_LEN = 240;
const MAX_TASK_ID = 48;
const MAX_TASK_SCHEDULE = 16;

export interface AgentTask {
  id: string;
  text: string;
  schedule: string;
}

async function taskSlotKey(taskSecret: string): Promise<string> {
  const h = await sha256Hex("flop-task-slot|" + taskSecret);
  return "t" + h.slice(0, 40);
}

export async function readOwnerTasks(
  fetchImpl: typeof fetch,
  ownerDid: string,
  taskSecret: string,
): Promise<AgentTask[]> {
  const ns = await didNoteNs(ownerDid);
  const key = await taskSlotKey(taskSecret);
  const value = await readNote(fetchImpl, ns, key);
  if (value === null) return [];
  let env: unknown;
  try {
    env = JSON.parse(value);
  } catch {
    return [];
  }
  if (env === null || typeof env !== "object" || Array.isArray(env)) return [];
  const e = env as Record<string, unknown>;
  const payload = e["payload"];
  const sig = e["sig"];
  if (typeof payload !== "string" || typeof sig !== "string") return [];
  let nonceCanon: string;
  try {
    nonceCanon = canonInt(e["nonce"] as number | string, "nonce");
  } catch {
    return [];
  }
  let ok = false;
  try {
    ok = await verifyB64url(pubRawFromDid(ownerDid), sig, noteSigInput(ns, key, nonceCanon, payload));
  } catch {
    return [];
  }
  if (!ok) return [];
  let arr: unknown;
  try {
    arr = JSON.parse(payload);
  } catch {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  const tasks: AgentTask[] = [];
  for (const t of arr.slice(0, MAX_TASKS)) {
    if (t === null || typeof t !== "object") continue;
    const to = t as Record<string, unknown>;
    const id = typeof to["id"] === "string" ? (to["id"] as string).slice(0, MAX_TASK_ID) : "";
    const text = typeof to["text"] === "string" ? (to["text"] as string).slice(0, MAX_TASK_LEN) : "";
    const schedule = typeof to["schedule"] === "string" ? (to["schedule"] as string).slice(0, MAX_TASK_SCHEDULE) : "once";
    if (id && text) tasks.push({ id, text, schedule });
  }
  return tasks;
}

export interface OwnerConfig {
  model: string;
  wake: number;
}
const CONFIG_WAKE_CHOICES = [1, 5, 10, 15, 30, 60];
const MAX_MODEL_LEN = 128;

export async function readOwnerConfig(
  fetchImpl: typeof fetch,
  ownerDid: string,
): Promise<OwnerConfig | null> {
  const ns = await didNoteNs(ownerDid);
  const [, shardKey] = await noteShardKey(ownerDid);
  const key = shardKey + "-config";
  const value = await readNote(fetchImpl, ns, key);
  if (value === null) return null;
  let envelope: unknown;
  try {
    envelope = JSON.parse(value);
  } catch {
    return null;
  }
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) return null;
  const e = envelope as Record<string, unknown>;
  const payload = e["payload"];
  const sig = e["sig"];
  if (typeof payload !== "string" || typeof sig !== "string") return null;
  let nonceCanon: string;
  try {
    nonceCanon = canonInt(e["nonce"] as number | string, "nonce");
  } catch {
    return null;
  }
  let ok = false;
  try {
    ok = await verifyB64url(pubRawFromDid(ownerDid), sig, noteSigInput(ns, key, nonceCanon, payload));
  } catch {
    return null;
  }
  if (!ok) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(payload);
  } catch {
    return null;
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return null;
  const o = obj as Record<string, unknown>;
  const model = o["model"];
  const wake = o["wake"];
  if (typeof model !== "string" || model.length === 0 || model.length > MAX_MODEL_LEN) return null;
  if (typeof wake !== "number" || !Number.isInteger(wake) || !CONFIG_WAKE_CHOICES.includes(wake)) return null;
  return { model, wake };
}

export const MAX_ACTIVITY_ENTRIES = 12;
const MAX_ACTIVITY_LEN = 120;
const MAX_ACTIVITY_URL = 7000;
// A trust-boundary scan: the gateway never stores an agent-supplied line that looks like a secret
// into a slot the owner reads back, even though the brain already filtered its own digest.
const ACTIVITY_SECRET_SHAPE = /[A-Fa-f0-9]{40,}|[A-Za-z0-9_-]{60,}/;
// Gateway-verifiable kibble digest shapes: a verb prefix plus a PUBLIC, grammar-legal job id. These are
// exempt from the secret scan so a hex-shaped job id does not silently drop RESULT/ATTEST lines from the
// feed - the exact half of the SAY-only-scan fix the gateway had not applied.
const KIBBLE_ACTIVITY_DIGEST = /^(claimed job |delivered result for job |attested job )[a-z0-9][a-z0-9_-]{0,47}$/;

export async function activitySlotKey(taskSecret: string): Promise<string> {
  const h = await sha256Hex("flop-activity-slot|" + taskSecret);
  return "a" + h.slice(0, 40);
}

export interface ActivityEntry {
  t: number;
  d: string;
}

// Append `entry` to the prior ring and trim the OLDEST entries until the percent-encoded note-set URL
// fits under MAX_ACTIVITY_URL - the SAME measure noteActivity aborts on. Trimming on JSON code-units
// (which diverges up to ~12x from the encoded URL on CJK/emoji) deadlocked the feed for a non-Latin agent
// below the 12-entry cap. An 88-char sig placeholder overestimates the real 86 so the
// fit is conservative. Pure + exported so it has a direct oracle. Always returns at least the newest entry.
export function fitActivityRing(prior: ActivityEntry[], entry: ActivityEntry, ns: string, key: string, ts: number): ActivityEntry[] {
  const SIG_PLACEHOLDER = "A".repeat(88);
  const encodedLen = (r: ActivityEntry[]): number =>
    urlNoteSet(ns, key, JSON.stringify({ payload: JSON.stringify(r), nonce: ts, sig: SIG_PLACEHOLDER })).length;
  let ring = [...prior, entry].slice(-MAX_ACTIVITY_ENTRIES);
  while (ring.length > 1 && encodedLen(ring) > MAX_ACTIVITY_URL) ring = ring.slice(1);
  return ring;
}

// Read back only a ring WE signed. A stranger who overwrites this world-writable slot does not verify
// under our did, so we drop the whole thing and start fresh rather than re-sign foreign lines as ours.
export async function readOwnActivityRing(
  fetchImpl: typeof fetch,
  ns: string,
  key: string,
  ourDid: string,
): Promise<ActivityEntry[]> {
  const value = await readNote(fetchImpl, ns, key);
  if (value === null) return [];
  let env: unknown;
  try {
    env = JSON.parse(value);
  } catch {
    return [];
  }
  if (env === null || typeof env !== "object" || Array.isArray(env)) return [];
  const e = env as Record<string, unknown>;
  const payload = e["payload"];
  const sig = e["sig"];
  if (typeof payload !== "string" || typeof sig !== "string") return [];
  let nonceCanon: string;
  try {
    nonceCanon = canonInt(e["nonce"] as number | string, "nonce");
  } catch {
    return [];
  }
  let ok = false;
  try {
    ok = await verifyB64url(pubRawFromDid(ourDid), sig, noteSigInput(ns, key, nonceCanon, payload));
  } catch {
    return [];
  }
  if (!ok) return [];
  let arr: unknown;
  try {
    arr = JSON.parse(payload);
  } catch {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  const out: ActivityEntry[] = [];
  for (const it of arr.slice(-MAX_ACTIVITY_ENTRIES)) {
    if (it === null || typeof it !== "object") continue;
    const o = it as Record<string, unknown>;
    const t = typeof o["t"] === "number" && Number.isFinite(o["t"]) ? Math.floor(o["t"] as number) : 0;
    const d = typeof o["d"] === "string" ? o["d"] : "";
    if (d) out.push({ t, d });
  }
  return out;
}

async function publishHealth(ctx: GatewayCtx, status: string, model: string): Promise<void> {
  const key = ctx.noteKey + "-health";
  const ts = ctx.now();
  const payload = JSON.stringify({ status, model, ts });
  const nonceCanon = canonInt(ts, "nonce");
  const sig = await signB64url(ctx.signingKey, noteSigInput(ctx.noteNs, key, nonceCanon, payload));
  const envelope = JSON.stringify({ payload, nonce: ts, sig });
  // redirect:manual like every other protocol write - a 3xx must not forward the note (and our ns/key)
  // to a Location host.
  await fetch(urlNoteSet(ctx.noteNs, key, envelope), { method: "GET", redirect: "manual" });
}

export class Gateway extends WorkerEntrypoint<Env> {
  #ctxPromise: Promise<GatewayCtx> | null = null;

  override async fetch(): Promise<Response> {
    return new Response("flop gateway: no public routes", { status: 404 });
  }

  override async scheduled(): Promise<void> {
    try {
      const ctx = await this.#buildCtx();
      const owner = this.env.OWNER_DID;
      await pollSteer({
        readGrants: owner
          ? () => readOwnerGrant((i: RequestInfo | URL, init?: RequestInit) => fetch(i, init), owner)
          : async () => [],
        applyGrant: (grant: Grant, now: number) => ctx.governor.applySteerGrant(grant, now),
        now: ctx.now,
      });
    } catch {
      /* never let a poll failure crash the cron */
    }
  }

  async sign(req: SignRequest): Promise<SignResult> {
    let ctx: GatewayCtx;
    try {
      ctx = await this.#buildCtx();
    } catch {
      return { status: "GATE_INTERNAL" };
    }
    return gatewaySign(req, ctx);
  }

  async complete(prompt: string): Promise<ModelResult> {
    let ctx: GatewayCtx | null = null;
    let model = "";
    let result: ModelResult;
    try {
      ctx = await this.#buildCtx();
      const ai = this.env.AI;
      const owner = this.env.OWNER_DID;
      const signed = owner ? await readOwnerConfig((i: RequestInfo | URL, init?: RequestInit) => fetch(i, init), owner) : null;
      model = (signed && signed.model) || this.env.MODEL_NAME || "";
      if (!ai || !model) {
        result = { status: "MODEL_ERROR" };
      } else {
        result = await modelComplete(prompt, {
          governor: ctx.governor,
          invoke: (p: string) => ai.run(model, { messages: [{ role: "user", content: p }] }),
          now: ctx.now,
        });
      }
    } catch {
      result = { status: "MODEL_ERROR" };
    }
    if (ctx && result.status !== "MODEL_BAD_REQUEST") {
      this.ctx.waitUntil(publishHealth(ctx, result.status, model).catch(() => {}));
    }
    return result;
  }

  async tasks(): Promise<AgentTask[]> {
    try {
      const owner = this.env.OWNER_DID;
      const secret = this.env.TASK_SECRET;
      if (!owner || !secret) return [];
      return await readOwnerTasks((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init), owner, secret);
    } catch {
      return [];
    }
  }

  async config(): Promise<OwnerConfig | null> {
    try {
      const owner = this.env.OWNER_DID;
      if (!owner) return null;
      return await readOwnerConfig((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init), owner);
    } catch {
      return null;
    }
  }

  // The private "what it did" feed. NOT a brain capability: the agent harness calls this only as a
  // side effect of an emit, so a hijacked brain cannot reach it to spam. The gateway is the trust
  // boundary - it scans + clamps the line, appends to a bounded ring, and SIGNS it into an unguessable
  // TASK_SECRET-derived slot in its own namespace, so the dashboard can reject a stranger's overwrite.
  async noteActivity(digest: string): Promise<{ stored: boolean }> {
    try {
      const secret = this.env.TASK_SECRET;
      if (!secret || typeof digest !== "string") return { stored: false };
      // Clamp on CODE POINTS (not UTF-16 units) so a trailing emoji is never split into a lone surrogate.
      const line = [...singleLine(digest)].slice(0, MAX_ACTIVITY_LEN).join("");
      // Exempt the known kibble digest shapes (verb + public job id) from the secret scan, so a
      // hex-shaped job id does not drop RESULT/ATTEST lines from the feed.
      if (!line) return { stored: false };
      if (!KIBBLE_ACTIVITY_DIGEST.test(line) && ACTIVITY_SECRET_SHAPE.test(line)) return { stored: false };
      const ctx = await this.#buildCtx();
      // STOP must mean dark on EVERY signing surface. noteActivity reaches the signing key and writes
      // to the protocol, so gate it on a live (non-empty-allow) grant - without this it would keep
      // writing under our did after the owner's kill switch, unmetered by the Governor.
      if (!(await ctx.governor.hasLiveGrant(ctx.now()))) return { stored: false };
      const key = await activitySlotKey(secret);
      const netFetch = (i: RequestInfo | URL, init?: RequestInit) => fetch(i, init);
      const prior = await readOwnActivityRing(netFetch, ctx.noteNs, key, ctx.ourDid);
      const ts = ctx.now();
      const nonceCanon = canonInt(ts, "nonce");
      const ring = fitActivityRing(prior, { t: ts, d: line }, ctx.noteNs, key, ts);
      const payload = JSON.stringify(ring);
      const sig = await signB64url(ctx.signingKey, noteSigInput(ctx.noteNs, key, nonceCanon, payload));
      const envelope = JSON.stringify({ payload, nonce: ts, sig });
      const url = urlNoteSet(ctx.noteNs, key, envelope);
      if (url.length > MAX_ACTIVITY_URL) return { stored: false };
      const res = await fetch(url, { method: "GET", redirect: "manual" });
      return { stored: res.status === 200 || res.status === 201 };
    } catch {
      return { stored: false };
    }
  }

  #buildCtx(): Promise<GatewayCtx> {
    if (this.#ctxPromise) return this.#ctxPromise;
    this.#ctxPromise = (async () => {
      const seedHex = this.env.KEY_SEED;
      const ourDid = this.env.OUR_DID;
      if (!seedHex || !ourDid) throw new Error("gateway not configured (KEY_SEED / OUR_DID)");
      const signingKey = await importSigningKey(hexToBytes(seedHex));
      const probeSig = await signB64url(signingKey, BOOT_PROBE);
      if (!(await verifyB64url(pubRawFromDid(ourDid), probeSig, BOOT_PROBE))) {
        throw new Error("gateway misconfigured: KEY_SEED does not match OUR_DID");
      }
      const noteNs = await didNoteNs(ourDid);
      const [, noteKey] = await noteShardKey(ourDid);
      const governor = this.env.GOVERNOR.get(this.env.GOVERNOR.idFromName(GOVERNOR_NAME));

      const ownerDid = this.env.OWNER_DID;
      if (ownerDid) {
        try {
          await governor.configure({ ownerPubHex: bytesToHex(pubRawFromDid(ownerDid)), agentDid: ourDid });
        } catch {
          /* fail-safe: an unconfigured Governor gates everything; nothing is opened by a failed configure */
        }
      }

      return {
        signingKey,
        ourDid,
        noteNs,
        noteKey,
        keyScope: noteKey,
        governor,
        // Board-match an ATTEST against the FULL sha256 the board holds for the job's result (computed from
        // the result text, not the board's own hash field, so it is bound to what the agent judged). The
        // board is untrusted: the worst a poisoned entry does is board-match a delivery it is itself
        // advertising (a ceiling-bounded reputation vote), never sign anything else. Own deliveries and any
        // failure return null -> no board-match.
        boardReader: (jobId: string): Promise<string | null> =>
          readJobResultHash((i: RequestInfo | URL, init?: RequestInit) => fetch(i, init), jobId, ourDid),
        now: () => Math.floor(Date.now() / 1000),
      };
    })();
    return this.#ctxPromise;
  }
}

export default Gateway;
