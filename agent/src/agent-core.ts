import type { SignRequest, SignResult } from "./gateway-core";
import type { ModelResult } from "./model-proxy";
import type { FetchGuardConfig, ResearchResult } from "./agent-fetch";
import type { SandboxProvider, SandboxResult, SandboxSpec } from "./agent-sandbox";
import type { Learning } from "./agent-memory";

export type BudgetClass = "reads" | "modelCalls" | "sandboxRuns" | "writes" | "memory";
export const BUDGET_CLASSES: readonly BudgetClass[] = ["reads", "modelCalls", "sandboxRuns", "writes", "memory"];

export interface TickBudget {
  reads: number;
  modelCalls: number;
  sandboxRuns: number;
  writes: number;
  // memory is metered so a hijacked brain cannot flood or evict its real learnings for free.
  memory: number;
}

function toCap(v: unknown): number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0;
}

export class BudgetTracker {
  #left: Record<BudgetClass, number>;
  readonly #cap: Record<BudgetClass, number>;

  constructor(budget: Partial<TickBudget> | null | undefined) {
    const b = (budget ?? {}) as Partial<TickBudget>;
    this.#cap = {
      reads: toCap(b.reads),
      modelCalls: toCap(b.modelCalls),
      sandboxRuns: toCap(b.sandboxRuns),
      writes: toCap(b.writes),
      memory: toCap(b.memory),
    };
    this.#left = { ...this.#cap };
  }

  spend(cls: BudgetClass): boolean {
    if (this.#left[cls] <= 0) return false;
    this.#left[cls] -= 1;
    return true;
  }

  remaining(cls: BudgetClass): number {
    return this.#left[cls];
  }

  spent(cls: BudgetClass): number {
    return this.#cap[cls] - this.#left[cls];
  }

  snapshot(): { cap: Record<BudgetClass, number>; spent: Record<BudgetClass, number> } {
    return {
      cap: { ...this.#cap },
      spent: {
        reads: this.spent("reads"),
        modelCalls: this.spent("modelCalls"),
        sandboxRuns: this.spent("sandboxRuns"),
        writes: this.spent("writes"),
        memory: this.spent("memory"),
      },
    };
  }
}

export interface OwnerTask {
  id: string;
  text: string;
  schedule: string;
}

export type TaskSchedule = "once" | "hourly" | "daily" | "weekly";
const SCHEDULE_SECONDS: Record<TaskSchedule, number> = { once: 0, hourly: 3600, daily: 86400, weekly: 604800 };
function asSchedule(v: unknown): TaskSchedule {
  const s = typeof v === "string" ? v.trim().toLowerCase() : "";
  return s === "hourly" || s === "daily" || s === "weekly" ? s : "once";
}

export function dueTasks(tasks: readonly OwnerTask[], runs: Record<string, number> | null | undefined, nowSec: number): OwnerTask[] {
  const now = typeof nowSec === "number" && Number.isFinite(nowSec) ? Math.floor(nowSec) : 0;
  const ledger = runs && typeof runs === "object" ? runs : {};
  const out: OwnerTask[] = [];
  for (const t of tasks) {
    if (t === null || typeof t !== "object") continue;
    const id = typeof t.id === "string" ? t.id : "";
    const text = typeof t.text === "string" ? t.text : "";
    if (id.length === 0 || text.length === 0) continue;
    const schedule = asSchedule(t.schedule);
    const last = ledger[id];
    const neverRun = typeof last !== "number" || !Number.isFinite(last);
    if (neverRun) {
      out.push({ id, text, schedule });
      continue;
    }
    if (schedule === "once") continue;
    if (now - last >= SCHEDULE_SECONDS[schedule]) out.push({ id, text, schedule });
  }
  return out;
}

export interface GatewayClient {
  sign(req: SignRequest): Promise<SignResult>;
  complete(prompt: string): Promise<ModelResult>;
  tasks(): Promise<OwnerTask[]>;
  config(): Promise<{ model: string; wake: number } | null>;
  // Optional: the private "what it did" feed. Harness-driven only (never exposed as a brain capability),
  // so a hijacked brain cannot reach it to spam. Optional so existing gateway mocks still typecheck.
  noteActivity?(digest: string): Promise<{ stored: boolean }>;
}

export interface ResearchFetcher {
  fetch(url: string): Promise<ResearchResult>;
}

export interface SandboxRunner {
  run(spec: SandboxSpec): Promise<SandboxResult>;
}

export interface BoardItem {
  id: string;
  raw: string;
  // Structured fields the planner needs to surface ATTESTABLE deliveries without re-parsing `raw`. A
  // delivered job carries a result and its board-posted hash; the hash is what an ATTEST must board-match.
  status: string;
  worker_did: string;
  title: string;
  result: string;
  result_hash: string;
}
export interface MailItem {
  raw: string;
}

export interface RoomInfo {
  room: string;
  kind: string;
  topic: string | null;
  lastSeq: number | null;
}

export interface RoomView {
  room: string;
  messages: { from: string; text: string; seq: number | null }[];
  lastSeq: number | null;
}

export interface MemoryClient {
  markSeen(jobIds: string[]): Promise<{ fresh: string[] }>;
  getLearnings(): Promise<Learning[]>;
  putLearning(text: string): Promise<{ stored: boolean }>;
  recordActed(jobId: string, action: string): Promise<{ stored: boolean }>;
  recordRecent(text: string): Promise<{ stored: boolean }>;
  getRecent(): Promise<string[]>;
  getHandoff(): Promise<string | null>;
  setHandoff(text: string): Promise<{ stored: boolean }>;
  getTaskRuns(): Promise<Record<string, number>>;
  recordTaskRun(taskId: string): Promise<{ stored: boolean }>;
  getLastThink(): Promise<number>;
  setLastThink(nowMs: number): Promise<{ stored: boolean }>;
  getIntroduced(): Promise<boolean>;
  setIntroduced(): Promise<{ stored: boolean }>;
}

export interface SendOutcome {
  sent: boolean;
  confirmed: boolean;
  detail?: string;
}

export type SignOk = Extract<SignResult, { status: "OK" }>;
export type EmitResult =
  | (SignOk & { delivered: boolean; confirmed: boolean; sent: boolean; detail?: string })
  | Exclude<SignResult, { status: "OK" }>;

export interface PassDeps {
  budget: Partial<TickBudget> | null | undefined;
  nick: string;
  gateway: GatewayClient;
  memory: MemoryClient;
  readBoard: () => Promise<BoardItem[]>;
  readMailbox: () => Promise<MailItem[]>;
  readRooms: () => Promise<RoomInfo[]>;
  lookRoom: (room: string) => Promise<RoomView>;
  postPresence: (nick: string) => Promise<void>;
  sendSigned: (result: SignOk) => Promise<SendOutcome>;
  research: ResearchFetcher;
  sandbox: SandboxRunner;
  planner: Planner;
  clock?: () => number;
  wakeDefaultMinutes?: number;
  log?: (event: PassEvent) => void;
}

export const CAP_BUDGET = { status: "BUDGET" } as const;
export type Budgeted<T> = T | typeof CAP_BUDGET;

export type PlannerSignRequest =
  | {
      shape: "kibble";
      verb: "CLAIM" | "RESULT" | "ATTEST";
      target: Record<string, unknown>;
      verdict?: { useful: boolean };
    }
  | { shape: "note"; value: string }
  | { shape: "say"; room: string; text: string };

export interface AgentCapabilities {
  model(prompt: string): Promise<Budgeted<ModelResult>>;
  research(url: string): Promise<Budgeted<ResearchResult>>;
  look(room: string): Promise<Budgeted<RoomView>>;
  runCode(spec: SandboxSpec): Promise<Budgeted<SandboxResult>>;
  emit(req: PlannerSignRequest): Promise<Budgeted<EmitResult>>;
  remember(text: string): Promise<Budgeted<{ stored: boolean }>>;
  handoff(text: string): Promise<Budgeted<{ stored: boolean }>>;
  taskDone(taskId: string): Promise<Budgeted<{ stored: boolean }>>;
}

// Why the plan loop stopped this wake, emitted from the trusted harness (fixed labels plus counts, no
// model text, so it is safe to log). This makes a silent wake legible: `done` with tasksDue=0 means the
// owner task never reached the prompt, `model_error` a failed model call, `transport_error` a gateway throw.
export type PlannerTerminal = "done" | "model_error" | "transport_error" | "budget" | "parse_exhausted" | "max_steps";
export interface PlannerOutcome {
  terminal: PlannerTerminal;
  steps: number; // model calls made this wake
  tasksDue: number; // owner tasks actually present in the prompt (0 => none were delivered)
  actions: number; // non-done commands the model chose
  emits: number; // public-emit commands specifically (say/claim/result/attest)
  parseFailures: number; // replies that were not one valid JSON command
  lastStatus?: string; // the model status on a model_error terminal
}

export interface Planner {
  plan(ctx: PassContext, caps: AgentCapabilities): Promise<PlannerOutcome | void>;
}

export interface PassContext {
  nick: string;
  board: BoardItem[];
  mailbox: MailItem[];
  rooms: RoomInfo[];
  freshJobIds: string[];
  learnings: Learning[];
  handoff: string | null;
  recent: string[];
  tasks: OwnerTask[];
  introduced: boolean;
}

const SECRET_SHAPE = /[A-Fa-f0-9]{40,}|[A-Za-z0-9_-]{60,}/;
function looksLikeSecret(text: unknown): boolean {
  return typeof text === "string" && SECRET_SHAPE.test(text);
}

function recentDigest(req: PlannerSignRequest): string | null {
  if (req.shape === "say") {
    // Clamp on CODE POINTS so a trailing emoji is never split into a lone surrogate that downstream
    // signing/encoding would choke on.
    const text = typeof req.text === "string" ? [...req.text].slice(0, 120).join("") : "";
    return "said in " + req.room + ": " + text;
  }
  if (req.shape === "kibble") {
    const target = req.target !== null && typeof req.target === "object" ? (req.target as Record<string, unknown>) : {};
    const jobId = typeof target["job_id"] === "string" ? (target["job_id"] as string) : "";
    const verbWord = req.verb === "CLAIM" ? "claimed job " : req.verb === "RESULT" ? "delivered result for job " : "attested job ";
    return jobId ? verbWord + jobId : null;
  }
  return null;
}

export function makeNonceAllocator(clock?: () => number): () => number {
  const now = clock ?? ((): number => Date.now());
  let last = 0;
  return (): number => {
    const ms = now();
    let n = typeof ms === "number" && Number.isFinite(ms) ? Math.floor(ms) * 1000 : 0;
    if (!Number.isSafeInteger(n) || n <= last) n = last + 1;
    last = n;
    return n;
  };
}

function buildCapabilities(budget: BudgetTracker, deps: PassDeps, allocNonce: () => number): AgentCapabilities {
  // A mechanical, harness-side same-wake dedup: `recent` is read once at the top of the pass and is
  // invisible to changes made mid-pass, so it cannot stop a hijacked planner re-posting the SAME line
  // several times in one wake. This set does, before any write budget is spent.
  const emittedThisTick = new Set<string>();
  return {
    async model(prompt: string): Promise<Budgeted<ModelResult>> {
      if (!budget.spend("modelCalls")) return CAP_BUDGET;
      return deps.gateway.complete(prompt);
    },
    async research(url: string): Promise<Budgeted<ResearchResult>> {
      if (!budget.spend("reads")) return CAP_BUDGET;
      return deps.research.fetch(url);
    },
    async look(room: string): Promise<Budgeted<RoomView>> {
      if (!budget.spend("reads")) return CAP_BUDGET;
      return deps.lookRoom(room);
    },
    async runCode(spec: SandboxSpec): Promise<Budgeted<SandboxResult>> {
      if (!budget.spend("sandboxRuns")) return CAP_BUDGET;
      return deps.sandbox.run(spec);
    },
    async emit(req: PlannerSignRequest): Promise<Budgeted<EmitResult>> {
      // Refuse an exact same-wake duplicate BEFORE spending the write, so a repeat costs nothing and
      // never reaches the public board a second time.
      const dupKey = recentDigest(req);
      if (dupKey && emittedThisTick.has(dupKey)) return { status: "GATE_DUP" };
      if (!budget.spend("writes")) return CAP_BUDGET;
      if (req.shape === "say" && looksLikeSecret(req.text)) return { status: "GATE_FORBIDDEN" };
      const full = { ...req, nonce: allocNonce() } as SignRequest;
      const result = await deps.gateway.sign(full);
      if (result.status !== "OK") return result;

      let out: SendOutcome;
      try {
        out = await deps.sendSigned(result);
      } catch {
        out = { sent: false, confirmed: false };
      }

      // Record on SENT, not confirmed. `recent` is the ONLY re-post / introduce-once suppressor, and a
      // signed, budget-charged, wire-accepted emit is an ACTION TAKEN whether or not the host echoes it
      // back yet. Gating it on a read-back the host can lag would re-introduce us in public every wake.
      // Delivery honesty rides in the digest text and the planner note, never in whether we record.
      if (out.sent) {
        if (req.shape === "kibble") {
          const target = req.target !== null && typeof req.target === "object" ? (req.target as Record<string, unknown>) : {};
          const jobId = typeof target["job_id"] === "string" ? (target["job_id"] as string) : "";
          if (jobId) {
            try {
              await deps.memory.recordActed(jobId, req.verb);
            } catch {
              /* memory is best-effort; the emit already landed */
            }
          }
        }
        // Mark this line emitted so an exact repeat later in the SAME wake is refused above.
        if (dupKey) emittedThisTick.add(dupKey);
        // The first successful SAY means we have spoken publicly - set the durable introduced flag so
        // introduce-once survives ring eviction and the 24h recent-TTL.
        if (req.shape === "say") {
          try {
            await deps.memory.setIntroduced();
          } catch {
            /* best-effort */
          }
        }
        // Only the SAY digest carries model-authored free text worth secret-scanning; a kibble digest is
        // just a verb plus a PUBLIC job id, and scanning it would drop the record on a hex-shaped id and
        // leave a RESULT/ATTEST with no re-post suppressor at all.
        if (dupKey && (req.shape !== "say" || !looksLikeSecret(dupKey))) {
          const line = out.confirmed ? dupKey : dupKey + " (sent, not yet confirmed)";
          try {
            await deps.memory.recordRecent(line);
          } catch {
            /* memory is best-effort; the emit already landed */
          }
        }
      }

      // The private "what it did" feed records only CONFIRMED deliveries (display-only; a missed line
      // loses nothing that matters). This is a harness side effect of a confirmed emit - never a brain
      // capability - so a hijacked planner cannot call it to spam the feed or burn protocol writes.
      if (out.confirmed && deps.gateway.noteActivity && dupKey && (req.shape !== "say" || !looksLikeSecret(dupKey))) {
        try {
          await deps.gateway.noteActivity(dupKey);
        } catch {
          /* best-effort; the emit already landed */
        }
      }
      return { ...result, delivered: out.confirmed, confirmed: out.confirmed, sent: out.sent, detail: out.detail };
    },
    async remember(text: string): Promise<Budgeted<{ stored: boolean }>> {
      if (!budget.spend("memory")) return CAP_BUDGET;
      if (looksLikeSecret(text)) return { stored: false };
      try {
        return await deps.memory.putLearning(text);
      } catch {
        return { stored: false };
      }
    },
    async handoff(text: string): Promise<Budgeted<{ stored: boolean }>> {
      if (!budget.spend("memory")) return CAP_BUDGET;
      if (looksLikeSecret(text)) return { stored: false };
      try {
        return await deps.memory.setHandoff(text);
      } catch {
        return { stored: false };
      }
    },
    async taskDone(taskId: string): Promise<Budgeted<{ stored: boolean }>> {
      if (!budget.spend("memory")) return CAP_BUDGET;
      try {
        return await deps.memory.recordTaskRun(taskId);
      } catch {
        return { stored: false };
      }
    },
  };
}

export type PassEvent =
  | { kind: "presence"; ok: boolean }
  | { kind: "read"; source: "board" | "mailbox" | "rooms"; count: number; ok: boolean }
  | { kind: "planner"; ok: boolean; outcome?: PlannerOutcome }
  | { kind: "budget-clamped"; note: string };

export interface PassReport {
  nick: string;
  boardCount: number;
  mailboxCount: number;
  freshCount: number;
  learningsCount: number;
  presencePosted: boolean;
  plannerOk: boolean;
  budget: { cap: Record<BudgetClass, number>; spent: Record<BudgetClass, number> };
}

async function resolveWakeMinutes(deps: PassDeps): Promise<number> {
  try {
    const cfg = await deps.gateway.config();
    if (cfg && Number.isInteger(cfg.wake) && cfg.wake > 0) return cfg.wake;
  } catch {
    /* fall through to the default */
  }
  const d = deps.wakeDefaultMinutes;
  return typeof d === "number" && Number.isInteger(d) && d > 0 ? d : 15;
}

export async function runPass(deps: PassDeps): Promise<PassReport> {
  const budget = new BudgetTracker(deps.budget);
  const log = deps.log ?? (() => {});

  const throttleNow = deps.clock ? deps.clock() : Date.now();
  const wakeMinutes = await resolveWakeMinutes(deps);
  let lastThink = 0;
  try {
    lastThink = await deps.memory.getLastThink();
  } catch {
    lastThink = 0;
  }
  if (lastThink > 0 && throttleNow - lastThink < wakeMinutes * 60_000) {
    return {
      nick: deps.nick,
      boardCount: 0,
      mailboxCount: 0,
      freshCount: 0,
      learningsCount: 0,
      presencePosted: false,
      plannerOk: false,
      budget: budget.snapshot(),
    };
  }
  try {
    await deps.memory.setLastThink(throttleNow);
  } catch {
    /* non-fatal */
  }

  let presencePosted = false;
  if (budget.spend("writes")) {
    try {
      await deps.postPresence(deps.nick);
      presencePosted = true;
    } catch {
      presencePosted = false;
    }
  }
  log({ kind: "presence", ok: presencePosted });

  const board = await safeRead(budget, deps.readBoard);
  log({ kind: "read", source: "board", count: board.length, ok: true });

  let freshJobIds: string[] = [];
  try {
    const seen = await deps.memory.markSeen(board.map((b) => b.id).filter((id) => id.length > 0));
    freshJobIds = Array.isArray(seen?.fresh) ? seen.fresh : [];
  } catch {
    freshJobIds = [];
  }

  const mailbox = await safeRead(budget, deps.readMailbox);
  log({ kind: "read", source: "mailbox", count: mailbox.length, ok: true });

  const rooms = await safeRead(budget, deps.readRooms);
  log({ kind: "read", source: "rooms", count: rooms.length, ok: true });

  let learnings: Learning[] = [];
  let handoff: string | null = null;
  try {
    learnings = await deps.memory.getLearnings();
  } catch {
    learnings = [];
  }
  try {
    handoff = await deps.memory.getHandoff();
  } catch {
    handoff = null;
  }

  let recent: string[] = [];
  try {
    recent = await deps.memory.getRecent();
  } catch {
    recent = [];
  }

  let introduced = false;
  try {
    introduced = await deps.memory.getIntroduced();
  } catch {
    introduced = false;
  }

  let tasks: OwnerTask[] = [];
  try {
    const t = await deps.gateway.tasks();
    tasks = Array.isArray(t) ? t : [];
  } catch {
    tasks = [];
  }

  let taskRuns: Record<string, number> = {};
  try {
    const r = await deps.memory.getTaskRuns();
    taskRuns = r && typeof r === "object" ? r : {};
  } catch {
    taskRuns = {};
  }
  const nowSec = Math.floor((deps.clock ? deps.clock() : Date.now()) / 1000);
  const due = dueTasks(tasks, taskRuns, nowSec);

  const allocNonce = makeNonceAllocator(deps.clock);
  const caps = buildCapabilities(budget, deps, allocNonce);
  let plannerOk = true;
  let outcome: PlannerOutcome | void = undefined;
  try {
    outcome = await deps.planner.plan({ nick: deps.nick, board, mailbox, rooms, freshJobIds, learnings, handoff, recent, tasks: due, introduced }, caps);
  } catch {
    plannerOk = false;
  }
  log({ kind: "planner", ok: plannerOk, outcome: outcome ?? undefined });

  return {
    nick: deps.nick,
    boardCount: board.length,
    mailboxCount: mailbox.length,
    freshCount: freshJobIds.length,
    learningsCount: learnings.length,
    presencePosted,
    plannerOk,
    budget: budget.snapshot(),
  };
}

const MAX_ITEMS_PER_READ = 200;

async function safeRead<T>(budget: BudgetTracker, read: () => Promise<T[]>): Promise<T[]> {
  if (!budget.spend("reads")) return [];
  try {
    const items = await read();
    if (!Array.isArray(items)) return [];
    return items.length > MAX_ITEMS_PER_READ ? items.slice(0, MAX_ITEMS_PER_READ) : items;
  } catch {
    return [];
  }
}

export type { FetchGuardConfig, ResearchResult, SandboxProvider, SandboxResult, SandboxSpec };
