import { WorkerEntrypoint } from "cloudflare:workers";
import { gatewaySign, type GatewayCtx, type SignRequest, type SignResult } from "./gateway-core";
import { modelComplete, type ModelResult } from "./model-proxy";
import { pollSteer } from "./steer-poll";
import { readNote } from "./protocol-read";
import type { Governor } from "./governor";
import type { Grant } from "./shared/grant";
import { bytesToHex, hexToBytes, sha256Hex, utf8 } from "./shared/bytes";
import { canonInt } from "./shared/canon";
import { noteSigInput, urlNoteSet } from "./shared/protocol";
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

async function publishHealth(ctx: GatewayCtx, status: string, model: string): Promise<void> {
  const key = ctx.noteKey + "-health";
  const ts = ctx.now();
  const payload = JSON.stringify({ status, model, ts });
  const nonceCanon = canonInt(ts, "nonce");
  const sig = await signB64url(ctx.signingKey, noteSigInput(ctx.noteNs, key, nonceCanon, payload));
  const envelope = JSON.stringify({ payload, nonce: ts, sig });
  await fetch(urlNoteSet(ctx.noteNs, key, envelope));
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
        boardReader: async () => null,
        now: () => Math.floor(Date.now() / 1000),
      };
    })();
    return this.#ctxPromise;
  }
}

export default Gateway;
