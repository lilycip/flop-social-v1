import { describe, it, expect } from "vitest";
import {
  runPass,
  BudgetTracker,
  makeNonceAllocator,
  type PassDeps,
  type Planner,
  type PassContext,
  type AgentCapabilities,
  CAP_BUDGET,
} from "../src/agent-core";
import type { SignRequest } from "../src/gateway-core";

interface Counts {
  sign: number;
  complete: number;
  research: number;
  sandbox: number;
  board: number;
  mailbox: number;
  rooms: number;
  look: number;
  presence: number;
  send: number;
  putLearning: number;
  setHandoff: number;
  recordActed: number;
  recordRecent: number;
  markSeen: number;
  getTaskRuns: number;
  recordTaskRun: number;
}

function makeDeps(over: Partial<PassDeps> & { budget: PassDeps["budget"]; planner: Planner }): {
  deps: PassDeps;
  counts: Counts;
} {
  const counts: Counts = {
    sign: 0,
    complete: 0,
    research: 0,
    sandbox: 0,
    board: 0,
    mailbox: 0,
    rooms: 0,
    look: 0,
    presence: 0,
    send: 0,
    putLearning: 0,
    setHandoff: 0,
    recordActed: 0,
    recordRecent: 0,
    markSeen: 0,
    getTaskRuns: 0,
    recordTaskRun: 0,
  };
  const deps: PassDeps = {
    nick: "agent",
    gateway: {
      async sign(_req: SignRequest) {
        counts.sign++;
        return { status: "OK", shape: "say", did: "did:key:z", signature: "s", nonce: "1", room: "r", text: "t" };
      },
      async complete(_p: string) {
        counts.complete++;
        return { status: "OK", text: "ok" };
      },
      async tasks() {
        return [];
      },
      async config() {
        return null;
      },
    },
    readBoard: async () => {
      counts.board++;
      return [];
    },
    readMailbox: async () => {
      counts.mailbox++;
      return [];
    },
    readRooms: async () => {
      counts.rooms++;
      return [];
    },
    lookRoom: async (room: string) => {
      counts.look++;
      return { room, messages: [], lastSeq: null };
    },
    postPresence: async () => {
      counts.presence++;
    },
    sendSigned: async () => {
      counts.send++;
      return { sent: true, confirmed: true };
    },
    research: {
      fetch: async (_url: string) => {
        counts.research++;
        return { status: "OK", text: "body", finalHost: "example.com" };
      },
    },
    sandbox: {
      run: async (_spec) => {
        counts.sandbox++;
        return { status: "OK", stdout: "out" };
      },
    },
    memory: {
      markSeen: async (ids: string[]) => {
        counts.markSeen++;
        return { fresh: ids };
      },
      getLearnings: async () => [],
      putLearning: async (_t: string) => {
        counts.putLearning++;
        return { stored: true };
      },
      recordActed: async (_j: string, _a: string) => {
        counts.recordActed++;
        return { stored: true };
      },
      recordRecent: async (_t: string) => {
        counts.recordRecent++;
        return { stored: true };
      },
      getRecent: async () => [],
      getHandoff: async () => null,
      setHandoff: async (_t: string) => {
        counts.setHandoff++;
        return { stored: true };
      },
      getTaskRuns: async () => {
        counts.getTaskRuns++;
        return {};
      },
      recordTaskRun: async (_id: string) => {
        counts.recordTaskRun++;
        return { stored: true };
      },
      getLastThink: async () => 0, // 0 => never throttled, so every test exercises a full think pass
      setLastThink: async (_n: number) => ({ stored: true }),
    },
    ...over,
  };
  return { deps, counts };
}

describe("BudgetTracker", () => {
  it("fails closed on missing / garbage / negative / non-integer caps", () => {
    for (const b of [null, undefined, {}, { reads: -1 }, { reads: NaN }, { reads: 1.5 }, { reads: "3" as unknown as number }]) {
      const t = new BudgetTracker(b as never);
      expect(t.spend("reads")).toBe(false);
      expect(t.remaining("reads")).toBe(0);
    }
  });

  it("allows exactly the cap and no more", () => {
    const t = new BudgetTracker({ reads: 2, modelCalls: 0, sandboxRuns: 0, writes: 0 });
    expect(t.spend("reads")).toBe(true);
    expect(t.spend("reads")).toBe(true);
    expect(t.spend("reads")).toBe(false);
    expect(t.spent("reads")).toBe(2);
    expect(t.spend("modelCalls")).toBe(false);
  });
});

describe("makeNonceAllocator - the wall owns the nonce, not the brain", () => {
  it("is strictly increasing within a wake even if the clock does not advance", () => {
    const alloc = makeNonceAllocator(() => 1_000_000);
    const a = alloc(),
      b = alloc(),
      c = alloc();
    expect(b).toBeGreaterThan(a);
    expect(c).toBeGreaterThan(b);
  });

  it("rises across wakes: a later clock base exceeds any earlier wake's nonces", () => {
    const wake1 = makeNonceAllocator(() => 1_000_000);
    const n1 = [wake1(), wake1(), wake1()];
    const wake2 = makeNonceAllocator(() => 1_060_000);
    expect(wake2()).toBeGreaterThan(Math.max(...n1));
  });

  it("never yields a NaN / unsafe / non-increasing nonce from a garbage clock", () => {
    const bad = makeNonceAllocator(() => NaN);
    const a = bad(),
      b = bad();
    expect(Number.isSafeInteger(a)).toBe(true);
    expect(Number.isSafeInteger(b)).toBe(true);
    expect(b).toBeGreaterThan(a);
  });

  it("every nonce is a positive safe integer within the 19-digit protocol bound", () => {
    const alloc = makeNonceAllocator(() => 1_750_000_000_000);
    for (let i = 0; i < 5; i++) {
      const n = alloc();
      expect(Number.isSafeInteger(n)).toBe(true);
      expect(n).toBeGreaterThan(0);
      expect(String(n).length).toBeLessThanOrEqual(19);
    }
  });
});

describe("emit - the brain cannot supply a nonce; the wall stamps a strictly-increasing one", () => {
  it("stamps a nonce onto every emit and the model never influences it", async () => {
    const seen: Array<number | string> = [];
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "say", room: "r", text: "one" });
        await caps.emit({ shape: "say", room: "r", text: "two" });
      },
    };
    const { deps } = makeDeps({ budget: { writes: 4 }, planner });
    deps.clock = () => 2_000_000;
    deps.gateway.sign = async (req: SignRequest) => {
      seen.push(req.nonce);
      return { status: "OK", shape: "say", did: "did:key:z", signature: "s", nonce: String(req.nonce), room: "r", text: "t" };
    };
    await runPass(deps);
    expect(seen).toHaveLength(2);
    expect(Number(seen[1])).toBeGreaterThan(Number(seen[0]));
  });

  it("SENDS every signed emit to the wire and records ACTED only when it LANDS", async () => {
    let last: unknown;
    const planner: Planner = {
      async plan(_c, caps) {
        last = await caps.emit({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-1" } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    deps.gateway.sign = async () => ({
      status: "OK", shape: "kibble", did: "did:key:z", signature: "s", nonce: "1", room: "kibble", text: "CLAIM job-1", boardMatch: false,
    });
    await runPass(deps);
    expect(counts.send).toBe(1);
    expect(counts.recordActed).toBe(1);
    expect(counts.recordRecent).toBe(1);
    expect((last as { delivered?: boolean }).delivered).toBe(true);
  });

  it("an UNDELIVERED emit is NOT recorded acted and reports delivered:false (the job stays open)", async () => {
    let last: unknown;
    const planner: Planner = {
      async plan(_c, caps) {
        last = await caps.emit({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-1" } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    deps.gateway.sign = async () => ({
      status: "OK", shape: "kibble", did: "did:key:z", signature: "s", nonce: "1", room: "kibble", text: "CLAIM job-1", boardMatch: false,
    });
    deps.sendSigned = async () => ({ sent: false, confirmed: false });
    await runPass(deps);
    expect(counts.recordActed).toBe(0);
    expect(counts.recordRecent).toBe(0);
    expect((last as { status: string; delivered?: boolean }).delivered).toBe(false);
  });

  it("a SENT-but-UNCONFIRMED emit (200, no read-back) is NOT recorded and reports delivered:false", async () => {
    let last: unknown;
    const planner: Planner = {
      async plan(_c, caps) {
        last = await caps.emit({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-1" } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    deps.gateway.sign = async () => ({
      status: "OK", shape: "kibble", did: "did:key:z", signature: "s", nonce: "1", room: "kibble", text: "CLAIM job-1", boardMatch: false,
    });
    deps.sendSigned = async () => { counts.send++; return { sent: true, confirmed: false }; };
    await runPass(deps);
    expect(counts.send).toBe(1);
    expect(counts.recordActed).toBe(0);
    expect(counts.recordRecent).toBe(0);
    expect((last as { delivered?: boolean }).delivered).toBe(false);
  });

  it("a signed emit that is gated by the Governor never reaches the wire", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "say", room: "r", text: "hi" });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    deps.gateway.sign = async () => ({ status: "GATE_CEILING" });
    await runPass(deps);
    expect(counts.send).toBe(0);
  });
});

describe("runPass - the facade caps a hostile planner", () => {
  it("lets through at most each class's budget, no matter how hard the planner pushes", async () => {
    const budget = { reads: 5, modelCalls: 1, sandboxRuns: 1, writes: 2 };
    let modelSeen = 0,
      researchSeen = 0,
      sandboxSeen = 0,
      emitSeen = 0,
      budgetHits = 0;
    const hostile: Planner = {
      async plan(_ctx, caps: AgentCapabilities) {
        for (let i = 0; i < 5; i++) {
          if ((await caps.model("p")) === CAP_BUDGET) budgetHits++;
          else modelSeen++;
          if ((await caps.research("https://x")) === CAP_BUDGET) budgetHits++;
          else researchSeen++;
          if ((await caps.runCode({ code: "c" })) === CAP_BUDGET) budgetHits++;
          else sandboxSeen++;
          if ((await caps.emit({ shape: "say", room: "r", text: "t" })) === CAP_BUDGET) budgetHits++;
          else emitSeen++;
        }
      },
    };
    const { deps, counts } = makeDeps({ budget, planner: hostile });
    const report = await runPass(deps);

    expect(counts.complete).toBe(1);
    expect(counts.board).toBe(1);
    expect(counts.mailbox).toBe(1);
    expect(counts.rooms).toBe(1);
    expect(counts.research).toBe(2);
    expect(counts.sandbox).toBe(1);
    expect(counts.sign).toBe(1);
    expect(counts.presence).toBe(1);
    expect(modelSeen).toBe(1);
    expect(researchSeen).toBe(2);
    expect(sandboxSeen).toBe(1);
    expect(emitSeen).toBe(1);
    expect(budgetHits).toBe(5 * 4 - (1 + 2 + 1 + 1));

    expect(report.budget.spent).toEqual({ reads: 5, modelCalls: 1, sandboxRuns: 1, writes: 2, memory: 0 });
    expect(report.presencePosted).toBe(true);
    expect(report.plannerOk).toBe(true);
  });

  it("the look cap is metered on reads: it spends a read, calls lookRoom, and is denied past the cap", async () => {
    let firstOk = false,
      secondBudget = false;
    const planner: Planner = {
      async plan(_ctx, caps) {
        firstOk = (await caps.look("lobby")) !== CAP_BUDGET;
        secondBudget = (await caps.look("lobby")) === CAP_BUDGET;
      },
    };
    const { deps, counts } = makeDeps({ budget: { reads: 4, modelCalls: 0, sandboxRuns: 0, writes: 0 }, planner });
    await runPass(deps);
    expect(firstOk).toBe(true);
    expect(secondBudget).toBe(true);
    expect(counts.look).toBe(1);
  });

  it("a null budget denies EVERYTHING: no presence, no reads, no effect reaches a dep", async () => {
    let anyCap = 0;
    const planner: Planner = {
      async plan(_ctx, caps) {
        if ((await caps.model("p")) !== CAP_BUDGET) anyCap++;
        if ((await caps.research("https://x")) !== CAP_BUDGET) anyCap++;
        if ((await caps.runCode({ code: "c" })) !== CAP_BUDGET) anyCap++;
        if ((await caps.emit({ shape: "say", room: "r", text: "t" })) !== CAP_BUDGET) anyCap++;
      },
    };
    const { deps, counts } = makeDeps({ budget: null, planner });
    const report = await runPass(deps);
    expect(anyCap).toBe(0);
    expect(counts).toMatchObject({ sign: 0, complete: 0, research: 0, sandbox: 0, board: 0, mailbox: 0, presence: 0 });
    expect(report.presencePosted).toBe(false);
    expect(report.boardCount).toBe(0);
  });
});

describe("runPass - nothing escapes to crash the cron", () => {
  it("a throwing board read fails soft to empty and the pass still completes", async () => {
    const planner: Planner = { async plan() {} };
    const { deps } = makeDeps({ budget: { reads: 4, modelCalls: 0, sandboxRuns: 0, writes: 1 }, planner });
    deps.readBoard = async () => {
      throw new Error("hostile board");
    };
    const report = await runPass(deps);
    expect(report.boardCount).toBe(0);
    expect(report.plannerOk).toBe(true);
  });

  it("clamps a hostile board flood to the per-read item cap (F4)", async () => {
    const planner: Planner = { async plan() {} };
    const { deps } = makeDeps({ budget: { reads: 4, modelCalls: 0, sandboxRuns: 0, writes: 1 }, planner });
    deps.readBoard = async () => Array.from({ length: 5000 }, (_v, i) => ({ id: `j${i}`, raw: `item-${i}` }));
    const report = await runPass(deps);
    expect(report.boardCount).toBe(200);
  });

  it("a throwing planner is recorded, never rethrown", async () => {
    const planner: Planner = {
      async plan() {
        throw new Error("brain exploded");
      },
    };
    const { deps } = makeDeps({ budget: { reads: 4, modelCalls: 1, sandboxRuns: 1, writes: 2 }, planner });
    const report = await runPass(deps);
    expect(report.plannerOk).toBe(false);
    expect(report.presencePosted).toBe(true);
  });

  it("a throwing presence post is non-fatal and still consumes its write unit", async () => {
    const planner: Planner = {
      async plan(_ctx, caps) {
        await caps.emit({ shape: "say", room: "r", text: "t" });
      },
    };
    const { deps, counts } = makeDeps({ budget: { reads: 2, modelCalls: 0, sandboxRuns: 0, writes: 1 }, planner });
    deps.postPresence = async () => {
      counts.presence++;
      throw new Error("presence failed");
    };
    const report = await runPass(deps);
    expect(report.presencePosted).toBe(false);
    expect(counts.presence).toBe(1);
    expect(counts.sign).toBe(0);
  });
});

describe("wake throttle - a cheap heartbeat that thinks only on the wake interval", () => {
  const T = 1_700_000_000_000;
  const okBudget = { reads: 8, modelCalls: 4, writes: 4 };
  const noopPlanner: Planner = { async plan() {} };

  it("a wake WITHIN the interval does not think: no board read, no model, no presence", async () => {
    const { deps, counts } = makeDeps({ budget: okBudget, planner: noopPlanner, wakeDefaultMinutes: 15 });
    deps.clock = () => T;
    deps.memory.getLastThink = async () => T - 5 * 60_000;
    const report = await runPass(deps);
    expect(counts.complete).toBe(0);
    expect(counts.board).toBe(0);
    expect(report.presencePosted).toBe(false);
  });

  it("thinks once the last think is older than the interval", async () => {
    const { deps, counts } = makeDeps({ budget: okBudget, planner: noopPlanner, wakeDefaultMinutes: 15 });
    deps.clock = () => T;
    deps.memory.getLastThink = async () => T - 20 * 60_000;
    await runPass(deps);
    expect(counts.board).toBe(1);
  });

  it("thinks on the FIRST wake (no prior think recorded)", async () => {
    const { deps, counts } = makeDeps({ budget: okBudget, planner: noopPlanner, wakeDefaultMinutes: 15 });
    deps.clock = () => T;
    deps.memory.getLastThink = async () => 0;
    await runPass(deps);
    expect(counts.board).toBe(1);
  });

  it("the owner's SIGNED config wake overrides the deploy default", async () => {
    const { deps, counts } = makeDeps({ budget: okBudget, planner: noopPlanner, wakeDefaultMinutes: 15 });
    deps.clock = () => T;
    deps.gateway.config = async () => ({ model: "@cf/x/y", wake: 30 });
    deps.memory.getLastThink = async () => T - 20 * 60_000;
    await runPass(deps);
    expect(counts.board).toBe(0);
  });
});

describe("the four memory protocols (4c-2)", () => {
  function capturingPlanner(): { planner: Planner; ctx: () => PassContext | null } {
    let seen: PassContext | null = null;
    return { planner: { async plan(c) { seen = c; } }, ctx: () => seen };
  }

  it("SEEN: the harness marks the board ids and hands the brain only the FRESH ones", async () => {
    const cap = capturingPlanner();
    const { deps, counts } = makeDeps({ budget: { reads: 4 }, planner: cap.planner });
    deps.readBoard = async () => [{ id: "a", raw: "{}" }, { id: "b", raw: "{}" }, { id: "", raw: "{}" }];
    deps.memory.markSeen = async (ids: string[]) => {
      counts.markSeen++;
      expect(ids).toEqual(["a", "b"]);
      return { fresh: ["b"] };
    };
    const report = await runPass(deps);
    expect(counts.markSeen).toBe(1);
    expect(cap.ctx()!.freshJobIds).toEqual(["b"]);
    expect(report.freshCount).toBe(1);
  });

  it("reads its OWN memory (learnings + handoff + recent) into the UNTRUSTED context", async () => {
    const cap = capturingPlanner();
    const { deps } = makeDeps({ budget: { reads: 4 }, planner: cap.planner });
    deps.memory.getLearnings = async () => [{ text: "kibble pays in attestations", created: 10 }];
    deps.memory.getHandoff = async () => "last wake: claimed job-7, check if delivered";
    deps.memory.getRecent = async () => ["said in lobby: Hello, I am jarvis"];
    await runPass(deps);
    expect(cap.ctx()!.learnings[0]!.text).toBe("kibble pays in attestations");
    expect(cap.ctx()!.handoff).toBe("last wake: claimed job-7, check if delivered");
    expect(cap.ctx()!.recent).toEqual(["said in lobby: Hello, I am jarvis"]);
  });

  it("SCHEDULING: the harness hands the brain only the DUE owner tasks, against the agent-owned ledger", async () => {
    const NOW = 1_000_000;
    const cap = capturingPlanner();
    const { deps, counts } = makeDeps({ budget: { reads: 4 }, planner: cap.planner });
    deps.clock = () => NOW * 1000;
    deps.gateway.tasks = async () => [
      { id: "presence", text: "keep presence", schedule: "hourly" },
      { id: "daily-post", text: "post the daily", schedule: "daily" },
      { id: "hello", text: "say hello once", schedule: "once" },
    ];
    deps.memory.getTaskRuns = async () => {
      counts.getTaskRuns++;
      return {
        presence: NOW - 3600, // exactly an hour ago -> DUE
        "daily-post": NOW - 600, // 10 min ago -> NOT due
        hello: NOW - 999999, // once, already ran -> never again
      };
    };
    await runPass(deps);
    expect(counts.getTaskRuns).toBe(1);
    expect(cap.ctx()!.tasks.map((t) => t.id)).toEqual(["presence"]);
  });

  it("SCHEDULING: a task-ledger read failure falls open to all tasks shown (safe, grant-bounded)", async () => {
    const cap = capturingPlanner();
    const { deps } = makeDeps({ budget: { reads: 4 }, planner: cap.planner });
    deps.gateway.tasks = async () => [{ id: "a", text: "x", schedule: "daily" }, { id: "b", text: "y", schedule: "weekly" }];
    deps.memory.getTaskRuns = async () => {
      throw new Error("ledger down");
    };
    await runPass(deps);
    expect(cap.ctx()!.tasks.map((t) => t.id)).toEqual(["a", "b"]);
  });

  it("ACTED: a SUCCESSFUL kibble emit is recorded automatically; a say emit is not", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-1" } });
        await caps.emit({ shape: "say", room: "r", text: "hi" });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    await runPass(deps);
    expect(counts.recordActed).toBe(1);
    expect(counts.recordRecent).toBe(2);
  });

  it("ACTED: a GATED (non-OK) emit is NOT recorded (dedup follows real work only)", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "kibble", verb: "CLAIM", target: { job_id: "job-1" } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    deps.gateway.sign = async () => ({ status: "GATE_CEILING" });
    await runPass(deps);
    expect(counts.recordActed).toBe(0);
  });

 it("LEARNINGS/HANDOFF writes are METERED: a hostile flood lands at most the memory cap", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        for (let i = 0; i < 50; i++) await caps.remember("learning number " + i);
        for (let i = 0; i < 50; i++) await caps.handoff("handoff note " + i);
      },
    };
    const { deps, counts } = makeDeps({ budget: { memory: 3 }, planner });
    await runPass(deps);
    expect(counts.putLearning + counts.setHandoff).toBe(3);
  });

  it("M6: a secret-shaped string is REFUSED (never persisted)", async () => {
    let rememberResult: unknown = null;
    const planner: Planner = {
      async plan(_c, caps) {
        rememberResult = await caps.remember("KEY=" + "a1b2c3d4".repeat(8));
        await caps.handoff("deadbeefcafebabe".repeat(4));
      },
    };
    const { deps, counts } = makeDeps({ budget: { memory: 4 }, planner });
    await runPass(deps);
    expect(counts.putLearning).toBe(0);
    expect(counts.setHandoff).toBe(0);
    expect(rememberResult).toEqual({ stored: false });
  });

  it("M6 does not flag legitimate prose (learnings have spaces, not long unbroken tokens)", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.remember("category build jobs are often spam, skip them");
      },
    };
    const { deps, counts } = makeDeps({ budget: { memory: 2 }, planner });
    await runPass(deps);
    expect(counts.putLearning).toBe(1);
  });

  it("M6 on the SAY egress path: a secret-shaped say is REFUSED before it is signed (DESIGN §6b)", async () => {
    let result: unknown = null;
    const planner: Planner = {
      async plan(_c, caps) {
        result = await caps.emit({ shape: "say", room: "lobby", text: "leak " + "a1b2c3d4".repeat(8) });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    await runPass(deps);
    expect(counts.sign).toBe(0);
    expect(result).toEqual({ status: "GATE_FORBIDDEN" });
  });

  it("M6 on SAY does not block ordinary prose (it still signs a normal message)", async () => {
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "say", room: "lobby", text: "hello everyone, I am working on job 7" });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    await runPass(deps);
    expect(counts.sign).toBe(1);
  });

  it("a KIBBLE RESULT is NOT egress-scanned (its body is hashed, not posted raw): a hex/base64 result still delivers", async () => {
    let result: unknown = null;
    const planner: Planner = {
      async plan(_c, caps) {
        result = await caps.emit({ shape: "kibble", verb: "RESULT", target: { job_id: "job-1", result: "the sha256 is " + "a1b2c3d4".repeat(8) } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    await runPass(deps);
    expect(counts.sign).toBe(1);
    expect((result as { status: string }).status).toBe("OK");
  });

  it("a secret-SHAPED recent DIGEST is not persisted into re-read memory (M6 on the recent write path)", async () => {
    const shaId = "a1b2c3d4".repeat(5);
    const planner: Planner = {
      async plan(_c, caps) {
        await caps.emit({ shape: "kibble", verb: "RESULT", target: { job_id: shaId, result: "the answer is 42" } });
      },
    };
    const { deps, counts } = makeDeps({ budget: { writes: 4 }, planner });
    await runPass(deps);
    expect(counts.send).toBe(1);
    expect(counts.recordRecent).toBe(0);
  });
});
