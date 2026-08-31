import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import type { AgentMemory } from "../src/agent-memory";

const NS = (env as unknown as { MEMORY: DurableObjectNamespace<AgentMemory> }).MEMORY;
let n = 0;
function mem() {
  return NS.get(NS.idFromName("mem-" + n++));
}
const DAY = 86400;
const TTL = 1_209_600;

describe("learnings: store, dedup, and read", () => {
  it("stores a new learning and reads it back as plain data", async () => {
    const m = mem();
    expect((await m.putLearning("kibble pays in attestations", 1000)).stored).toBe(true);
    const rows = await m.getLearnings(1000);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.text).toBe("kibble pays in attestations");
    expect(rows[0]!.created).toBe(1000);
  });

  it("rejects a non-string / empty / whitespace learning without storing", async () => {
    const m = mem();
    expect((await m.putLearning(42 as unknown as string, 1000)).stored).toBe(false);
    expect((await m.putLearning("   ", 1000)).stored).toBe(false);
    expect((await m.getLearnings(1000))).toEqual([]);
  });

  it("clamps an over-long learning to the cap", async () => {
    const m = mem();
    await m.putLearning("x".repeat(5000), 1000);
    expect((await m.getLearnings(1000))[0]!.text.length).toBe(512);
  });
});

describe("M1: a re-write cannot refresh the immutable creation clock", () => {
  it("a duplicate put is a no-op and does NOT move `created` forward", async () => {
    const m = mem();
    expect((await m.putLearning("poison", 1000)).stored).toBe(true);
    expect((await m.putLearning("poison", 500_000)).stored).toBe(false);
    expect((await m.getLearnings(500_000))[0]!.created).toBe(1000);
  });

  it("re-writing within the TTL does not extend its life: it still expires on the ORIGINAL schedule", async () => {
    const m = mem();
    await m.putLearning("poison", 1000);
    for (let t = 1000 + DAY; t < 1000 + TTL; t += DAY) {
      expect((await m.putLearning("poison", t)).stored).toBe(false);
    }
    expect(await m.getLearnings(1000 + TTL + 1)).toEqual([]);
  });

  it("a TTL-expired learning is pruned on read", async () => {
    const m = mem();
    await m.putLearning("stale", 1000);
    expect(await m.getLearnings(1000 + TTL + 1)).toEqual([]);
  });
});

describe("M1: eviction is by AGE-SINCE-CREATION, never write recency", () => {
  it("over the cap, the OLDEST-created learnings are evicted (not the newest)", async () => {
    const m = mem();
    for (let i = 0; i < 260; i++) {
      await m.putLearning("L" + i, 1000 + i);
    }
    const rows = await m.getLearnings(1000 + 300);
    expect(rows.length).toBe(256);
    const texts = new Set(rows.map((r) => r.text));
    expect(texts.has("L0")).toBe(false);
    expect(texts.has("L3")).toBe(false);
    expect(texts.has("L259")).toBe(true);
  });
});

describe("M5: acted ledger (dedup) - NOT a safety guarantee, just convenience", () => {
  it("records an acted job once; a second identical record is a no-op", async () => {
    const m = mem();
    expect((await m.recordActed("job-1", "CLAIM", 1000)).stored).toBe(true);
    expect((await m.recordActed("job-1", "CLAIM", 2000)).stored).toBe(false);
    expect(await m.hasActed("job-1", "CLAIM")).toBe(true);
    expect(await m.hasActed("job-1", "RESULT")).toBe(false);
    expect(await m.hasActed("job-2", "CLAIM")).toBe(false);
  });

  it("caps the acted ledger and evicts the oldest (durable-until-512-newer, not permanent)", async () => {
    const m = mem();
    for (let i = 0; i < 520; i++) await m.recordActed("j" + i, "CLAIM", 1000 + i);
    expect((await m.snapshot()).acted).toBe(512);
    expect(await m.hasActed("j0", "CLAIM")).toBe(false);
    expect(await m.hasActed("j519", "CLAIM")).toBe(true);
  });
});

describe("M5: seen window (bounded dedup with its own quota)", () => {
  it("returns only the FRESH (unseen) ids and marks them", async () => {
    const m = mem();
    expect((await m.markSeen(["a", "b", "c"], 1000)).fresh.sort()).toEqual(["a", "b", "c"]);
    expect((await m.markSeen(["a", "b", "d"], 2000)).fresh).toEqual(["d"]);
  });

  it("ignores non-string ids and caps the batch", async () => {
    const m = mem();
    const r = await m.markSeen(["ok", 5, null, "  "], 1000);
    expect(r.fresh).toEqual(["ok"]);
  });

  it("caps the seen window at 2048 and evicts the oldest", async () => {
    const m = mem();
    for (let b = 0; b < 9; b++) {
      const batch: string[] = [];
      for (let i = 0; i < 250; i++) batch.push("s" + (b * 250 + i));
      await m.markSeen(batch, 1000 + b);
    }
    expect((await m.snapshot()).seen).toBe(2048);
    expect((await m.markSeen(["s0"], 5000)).fresh).toEqual(["s0"]);
    expect((await m.markSeen(["s2249"], 5000)).fresh).toEqual([]);
  });
});

describe("handoff: the single overwritten note to the next wake", () => {
  it("stores, overwrites, and reads back the handoff; blank clears it", async () => {
    const m = mem();
    expect(await m.getHandoff()).toBeNull();
    expect((await m.setHandoff("claimed job-7, next check if delivered", 1000)).stored).toBe(true);
    expect(await m.getHandoff()).toBe("claimed job-7, next check if delivered");
    await m.setHandoff("nothing in flight", 2000);
    expect(await m.getHandoff()).toBe("nothing in flight");
    expect((await m.setHandoff("   ", 3000)).stored).toBe(false);
    expect(await m.getHandoff()).toBeNull();
  });

  it("clamps an over-long handoff note", async () => {
    const m = mem();
    await m.setHandoff("y".repeat(5000), 1000);
    expect((await m.getHandoff())!.length).toBe(1024);
  });
});

describe("snapshot returns counts only", () => {
  it("counts each store", async () => {
    const m = mem();
    await m.putLearning("one", 1000);
    await m.recordActed("j", "CLAIM", 1000);
    await m.markSeen(["s1", "s2"], 1000);
    await m.recordRecent("said in lobby: hi", 1000);
    expect(await m.snapshot()).toEqual({ learnings: 1, acted: 1, seen: 2, recent: 1 });
  });
});

describe("recent-actions ledger: what the brain already DID (a display feed, not safety)", () => {
  const DAY = 86_400;

  it("stores a digest and reads it back NEWEST FIRST", async () => {
    const m = mem();
    expect((await m.recordRecent("said in lobby: one", 1000)).stored).toBe(true);
    expect((await m.recordRecent("claimed job job-7", 2000)).stored).toBe(true);
    expect(await m.getRecent(2000)).toEqual(["claimed job job-7", "said in lobby: one"]);
  });

  it("dedups by exact text and (M1) a repeat does NOT refresh the creation clock", async () => {
    const m = mem();
    expect((await m.recordRecent("said in lobby: hello", 1000)).stored).toBe(true);
    expect((await m.recordRecent("said in lobby: hello", 40_000)).stored).toBe(false);
    expect(await m.getRecent(1000 + DAY + 1)).toEqual([]);
  });

  it("has a hard TTL: a recent action is gone after a day", async () => {
    const m = mem();
    await m.recordRecent("said in lobby: stale", 1000);
    expect(await m.getRecent(1000 + DAY - 1)).toEqual(["said in lobby: stale"]);
    expect(await m.getRecent(1000 + DAY + 1)).toEqual([]);
  });

  it("evicts by AGE-SINCE-CREATION past its own quota (never write recency)", async () => {
    const m = mem();
    await m.recordRecent("act 0", 1000);
    await m.recordRecent("act 0", 5000);
    for (let i = 1; i < 40; i++) await m.recordRecent("act " + i, 6000 + i);
    expect((await m.snapshot()).recent).toBe(32);
    const rows = await m.getRecent(6100);
    expect(rows).not.toContain("act 0");
    expect(rows[0]).toBe("act 39");
  });

  it("garbage input never crashes a write", async () => {
    const m = mem();
    expect((await m.recordRecent(42 as unknown as string, 1000)).stored).toBe(false);
    expect((await m.recordRecent("   ", 1000)).stored).toBe(false);
    expect(await m.getRecent(1000)).toEqual([]);
  });
});

describe("task-run ledger: the agent-owned recurrence clock (scheduling)", () => {
  it("records a run and reads it back as task_id -> last_run seconds", async () => {
    const m = mem();
    expect((await m.recordTaskRun("presence", 1000)).stored).toBe(true);
    expect((await m.recordTaskRun("daily-post", 2000)).stored).toBe(true);
    expect(await m.getTaskRuns()).toEqual({ presence: 1000, "daily-post": 2000 });
  });

  it("UPSERTs: a second run of the same task moves last_run forward, not a duplicate row", async () => {
    const m = mem();
    await m.recordTaskRun("presence", 1000);
    await m.recordTaskRun("presence", 5000);
    expect(await m.getTaskRuns()).toEqual({ presence: 5000 });
  });

  it("rejects a non-string / empty / whitespace task id without recording", async () => {
    const m = mem();
    expect((await m.recordTaskRun(42 as unknown as string, 1000)).stored).toBe(false);
    expect((await m.recordTaskRun("   ", 1000)).stored).toBe(false);
    expect(await m.getTaskRuns()).toEqual({});
  });

  it("clamps an over-long task id to the cap", async () => {
    const m = mem();
    await m.recordTaskRun("z".repeat(500), 1000);
    expect(Object.keys(await m.getTaskRuns())[0]!.length).toBe(128);
  });

  it("owns the clock (M1): under TEST_MODE a caller now is honoured; the harness compares its own clock", async () => {
    const m = mem();
    await m.recordTaskRun("t", 12345);
    expect((await m.getTaskRuns()).t).toBe(12345);
  });

  it("bounds the ledger to its own quota, evicting the OLDEST-run ids first (M5)", async () => {
    const m = mem();
    for (let i = 0; i < 70; i++) await m.recordTaskRun("task-" + i, 1000 + i);
    const runs = await m.getTaskRuns();
    expect(Object.keys(runs).length).toBe(64);
    expect(runs["task-0"]).toBeUndefined();
    expect(runs["task-5"]).toBeUndefined();
    expect(runs["task-6"]).toBe(1006);
    expect(runs["task-69"]).toBe(1069);
  });
});

describe("wake throttle: the last-think timestamp (single row, harness-written)", () => {
  it("is 0 before any think, and reads back what was set", async () => {
    const m = mem();
    expect(await m.getLastThink()).toBe(0);
    expect((await m.setLastThink(1_700_000_000_000)).stored).toBe(true);
    expect(await m.getLastThink()).toBe(1_700_000_000_000);
  });

  it("overwrites on each think (one row, latest wins)", async () => {
    const m = mem();
    await m.setLastThink(1000);
    await m.setLastThink(2000);
    expect(await m.getLastThink()).toBe(2000);
  });

  it("refuses a non-positive / non-number value and keeps the last good one", async () => {
    const m = mem();
    await m.setLastThink(5000);
    expect((await m.setLastThink(0)).stored).toBe(false);
    expect((await m.setLastThink(-1)).stored).toBe(false);
    expect((await m.setLastThink("x" as unknown as number)).stored).toBe(false);
    expect(await m.getLastThink()).toBe(5000);
  });
});
