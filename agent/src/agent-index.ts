import { runPass, type PassDeps, type BoardItem, type MailItem, type RoomInfo, type RoomView, type MemoryClient, type SignOk, type SendOutcome } from "./agent-core";
import { makeModelPlanner } from "./agent-planner";
import type { AgentMemory } from "./agent-memory";
import { researchFetch, type FetchGuardConfig } from "./agent-fetch";
import { runSandboxJob, type SandboxProvider, type SandboxSpec, type SandboxResult } from "./agent-sandbox";
import { readBoard as readBoardWire, readRoom as readRoomWire, readRooms as readRoomsWire, readNote as readNoteWire } from "./protocol-read";
import { urlNoteSet, urlSaySigned, urlNoteSetSigned } from "./shared/protocol";
import { nameIsBearerSecret } from "./shared/names";
import type { Gateway } from "./index";

export { AgentMemory } from "./agent-memory";

const PRESENCE_NS = "kibble";
const mailboxRoom = (nick: string): string => "mb-" + nick;

function boardRaw(jobs: readonly unknown[]): BoardItem[] {
  return jobs.map((j) => {
    const jd = j !== null && typeof j === "object" ? (j as Record<string, unknown>) : {};
    const id = typeof jd["job_id"] === "string" ? (jd["job_id"] as string) : "";
    return { id, raw: JSON.stringify(j) };
  });
}

function buildMemory(env: AgentEnv): MemoryClient {
  const stub = env.MEMORY.get(env.MEMORY.idFromName("agent"));
  return {
    markSeen: (jobIds) => stub.markSeen(jobIds),
    getLearnings: () => stub.getLearnings(),
    putLearning: (text) => stub.putLearning(text),
    recordActed: (jobId, action) => stub.recordActed(jobId, action),
    recordRecent: (text) => stub.recordRecent(text),
    getRecent: () => stub.getRecent(),
    getHandoff: () => stub.getHandoff(),
    setHandoff: (text) => stub.setHandoff(text),
    getTaskRuns: () => stub.getTaskRuns(),
    recordTaskRun: (taskId) => stub.recordTaskRun(taskId),
    getLastThink: () => stub.getLastThink(),
    setLastThink: (nowMs) => stub.setLastThink(nowMs),
    getIntroduced: () => stub.getIntroduced(),
    setIntroduced: () => stub.setIntroduced(),
  };
}
function mailRaw(messages: readonly unknown[]): MailItem[] {
  return messages.map((m) => ({ raw: JSON.stringify(m) }));
}

const MAX_LOOK_MSGS = 20;

async function lookRoomView(netFetch: typeof fetch, room: string): Promise<RoomView> {
  if (nameIsBearerSecret(room)) return { room, messages: [], lastSeq: null };
  const rr = await readRoomWire(netFetch, room);
  const recent = rr.messages.slice(-MAX_LOOK_MSGS).map((m) => ({ from: m.from, text: m.text, seq: m.seq }));
  return { room: rr.room, messages: recent, lastSeq: rr.lastSeq };
}

const MAX_WRITE_URL = 7000;

const CONFIRM_ATTEMPTS = 3;
const CONFIRM_RETRY_MS = 400;
const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function sendSignedWire(
  netFetch: typeof fetch,
  result: SignOk,
  sleep: (ms: number) => Promise<void> = realSleep,
): Promise<SendOutcome> {
  try {
    let writeUrl: string;
    let confirm: () => Promise<boolean>;
    if (result.shape === "say" || result.shape === "kibble") {
      const room = result.room;
      const text = result.text;
      if (!room || text == null) return { sent: false, confirmed: false, detail: "bad-shape" };
      const nonce = result.nonce;
      writeUrl = urlSaySigned(room, result.did, result.signature, nonce, text);
      // Capture the room tail BEFORE writing, so confirm only accepts a message that arrived AFTER our
      // write - never a stale identical prior post, which would confirm a write that never landed.
      // `since` also bounds the read to the few new messages, so a busy room past
      // the 200-cap cannot silently hide our own message at the tail.
      let beforeSeq: number | null = null;
      try {
        beforeSeq = (await readRoomWire(netFetch, room)).lastSeq;
      } catch {
        beforeSeq = null;
      }
      confirm = async () => {
        const r = await readRoomWire(netFetch, room, beforeSeq != null ? { since: beforeSeq } : undefined);
        return r.messages.some((m) => {
          if (m.from !== result.did) return false;
          // Require POSITIVE proof, never the ABSENCE of a disqualifier: our exact echoed nonce is
          // proof on its own; otherwise the message must be PROVABLY newer than the pre-write tail
          // (both baseline and seq present) AND match our text. A missing seq proves nothing, so it can
          // no longer let a stale identical prior post confirm a write that never landed.
          const nonceEcho = m.nonce != null && m.nonce === String(nonce);
          const provenNewer = beforeSeq != null && m.seq != null && m.seq > beforeSeq;
          return nonceEcho || (provenNewer && m.text === text);
        });
      };
    } else {
      const ns = result.namespace;
      const key = result.key;
      const value = result.value;
      if (!ns || !key || value == null) return { sent: false, confirmed: false, detail: "bad-shape" };
      writeUrl = urlNoteSetSigned(ns, key, result.did, result.signature, result.nonce, value);
      confirm = async () => (await readNoteWire(netFetch, ns, key)) === value;
    }
    if (writeUrl.length > MAX_WRITE_URL) return { sent: false, confirmed: false, detail: "too-long" };
    const resp = await netFetch(writeUrl, { method: "GET", redirect: "manual" });
    if (!(resp.status === 200 || resp.status === 201)) return { sent: false, confirmed: false, detail: "http-" + resp.status };
    let confirmed = false;
    for (let i = 0; i < CONFIRM_ATTEMPTS; i++) {
      try {
        confirmed = await confirm();
      } catch {
        confirmed = false;
      }
      if (confirmed) break;
      if (i < CONFIRM_ATTEMPTS - 1) await sleep(CONFIRM_RETRY_MS);
    }
    return { sent: true, confirmed };
  } catch {
    return { sent: false, confirmed: false };
  }
}

export function makeProtocolIO(
  netFetch: typeof fetch,
  nick: string,
  opts?: { sleep?: (ms: number) => Promise<void> },
): Pick<PassDeps, "readBoard" | "readMailbox" | "readRooms" | "lookRoom" | "postPresence" | "sendSigned"> {
  const sleep = opts?.sleep;
  return {
    readBoard: async () => boardRaw((await readBoardWire(netFetch)).jobs),
    readMailbox: async () => mailRaw((await readRoomWire(netFetch, mailboxRoom(nick))).messages),
    readRooms: async (): Promise<RoomInfo[]> => readRoomsWire(netFetch),
    lookRoom: (room: string): Promise<RoomView> => lookRoomView(netFetch, room),
    postPresence: async (n: string) => {
      const value = String(Math.floor(Date.now() / 1000));
      await netFetch(urlNoteSet(PRESENCE_NS, "hb-" + n, value), { method: "GET", redirect: "manual" });
    },
    sendSigned: (result: SignOk) => sendSignedWire(netFetch, result, sleep),
  };
}

interface AgentEnv {
  GATEWAY: Service<Gateway>;
  SANDBOX?: DurableObjectNamespace;
  MEMORY: DurableObjectNamespace<AgentMemory>;
  NICK?: string;
  RESEARCH_ALLOW_HOSTS?: string;
  RESEARCH_DENY_HOSTS?: string;
  TECHNOCORE_BASE?: string;
  BUDGET_READS?: string;
  BUDGET_MODEL?: string;
  BUDGET_SANDBOX?: string;
  BUDGET_WRITES?: string;
  BUDGET_MEMORY?: string;
  WAKE_MINUTES?: string;
}

const DEFAULT_BUDGET = { reads: 8, modelCalls: 4, sandboxRuns: 2, writes: 4, memory: 4 } as const;
const WAKE_LADDER = [1, 5, 10, 15, 30, 60];

function parseCap(v: string | undefined, fallback: number): number {
  if (v == null) return fallback;
  const n = Number(v);
  return Number.isSafeInteger(n) && n >= 0 ? n : 0;
}

function parseWakeDefault(v: string | undefined): number {
  const n = v == null ? NaN : Number(v);
  return Number.isInteger(n) && WAKE_LADDER.includes(n) ? n : 15;
}

function hostList(v: string | undefined): string[] {
  if (!v) return [];
  return v
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
}

const KNOWN_TECHNOCORE_HOSTS = ["technocore.chat", "www.technocore.chat"] as const;

function technocoreHost(base: string | undefined): string[] {
  if (!base) return [];
  try {
    return [new URL(base).hostname.toLowerCase()];
  } catch {
    return [];
  }
}

function buildSandboxProvider(_env: AgentEnv): SandboxProvider {
  return {
    randomId: () => crypto.randomUUID(),
    async create(): Promise<never> {
      throw new Error("sandbox not wired");
    },
  };
}

function buildDeps(env: AgentEnv): PassDeps {
  const nick = env.NICK && env.NICK.length > 0 ? env.NICK : "agent";

  const netFetch = ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init)) as typeof fetch;

  const guardCfg: FetchGuardConfig = {
    allowHosts: hostList(env.RESEARCH_ALLOW_HOSTS),
    denyHosts: [
      ...KNOWN_TECHNOCORE_HOSTS,
      ...hostList(env.RESEARCH_DENY_HOSTS),
      ...technocoreHost(env.TECHNOCORE_BASE),
    ],
    maxBytes: 1_000_000,
  };

  const provider = buildSandboxProvider(env);

  return {
    budget: {
      reads: parseCap(env.BUDGET_READS, DEFAULT_BUDGET.reads),
      modelCalls: parseCap(env.BUDGET_MODEL, DEFAULT_BUDGET.modelCalls),
      sandboxRuns: parseCap(env.BUDGET_SANDBOX, DEFAULT_BUDGET.sandboxRuns),
      writes: parseCap(env.BUDGET_WRITES, DEFAULT_BUDGET.writes),
      memory: parseCap(env.BUDGET_MEMORY, DEFAULT_BUDGET.memory),
    },
    nick,
    gateway: {
      sign: (req) => env.GATEWAY.sign(req),
      complete: (prompt) => env.GATEWAY.complete(prompt),
      tasks: () => env.GATEWAY.tasks(),
      config: () => env.GATEWAY.config(),
      noteActivity: (digest: string) => env.GATEWAY.noteActivity(digest),
    },
    memory: buildMemory(env),
    wakeDefaultMinutes: parseWakeDefault(env.WAKE_MINUTES),
    ...makeProtocolIO(netFetch, nick),
    research: { fetch: (url: string) => researchFetch(url, guardCfg, (i, init) => fetch(i, init)) },
    sandbox: { run: (spec: SandboxSpec): Promise<SandboxResult> => runSandboxJob(spec, provider) },
    planner: makeModelPlanner(),
    clock: () => Date.now(),
  };
}

export default {
  async fetch(): Promise<Response> {
    return new Response("flop agent: no public routes", { status: 404 });
  },

  async scheduled(_controller: ScheduledController, env: AgentEnv, _ctx: ExecutionContext): Promise<void> {
    try {
      await runPass(buildDeps(env));
    } catch {
      /* never let a wake crash the cron; the next tick retries */
    }
  },
};
