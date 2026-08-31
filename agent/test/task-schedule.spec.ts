import { describe, it, expect } from "vitest";
import { dueTasks, type OwnerTask } from "../src/agent-core";

const t = (id: string, schedule: string, text = "do " + id): OwnerTask => ({ id, text, schedule });
const HOUR = 3600;
const DAY = 86400;
const WEEK = 604800;
const NOW = 1_000_000;

describe("dueTasks - the recurrence oracle", () => {
  it("a never-run task is always due, whatever its schedule", () => {
    const tasks = [t("a", "once"), t("b", "hourly"), t("c", "daily"), t("d", "weekly")];
    expect(dueTasks(tasks, {}, NOW).map((x) => x.id)).toEqual(["a", "b", "c", "d"]);
  });

  it("a 'once' task that has run is never due again", () => {
    expect(dueTasks([t("a", "once")], { a: NOW - WEEK }, NOW)).toEqual([]);
  });

  it("a recurring task is due only once its period has elapsed since the last run", () => {
    expect(dueTasks([t("h", "hourly")], { h: NOW - (HOUR - 1) }, NOW)).toEqual([]);
    expect(dueTasks([t("h", "hourly")], { h: NOW - HOUR }, NOW).map((x) => x.id)).toEqual(["h"]);
    expect(dueTasks([t("d", "daily")], { d: NOW - (DAY - 1) }, NOW)).toEqual([]);
    expect(dueTasks([t("d", "daily")], { d: NOW - DAY }, NOW).map((x) => x.id)).toEqual(["d"]);
    expect(dueTasks([t("w", "weekly")], { w: NOW - (WEEK - 1) }, NOW)).toEqual([]);
    expect(dueTasks([t("w", "weekly")], { w: NOW - WEEK }, NOW).map((x) => x.id)).toEqual(["w"]);
  });

  it("normalises an unknown/absent schedule to 'once' (runs at most once, never an unbounded repeat)", () => {
    expect(dueTasks([t("x", "every-blue-moon")], { x: NOW - WEEK }, NOW)).toEqual([]);
    expect(dueTasks([t("x", "")], {}, NOW).map((i) => i.id)).toEqual(["x"]);
    expect(dueTasks([t("x", "nonsense")], {}, NOW)[0]!.schedule).toBe("once");
  });

  it("normalises case and surrounding whitespace so a dashboard's 'Hourly ' is not downgraded to once", () => {
    expect(dueTasks([t("h", "Hourly ")], { h: NOW - (HOUR + 60) }, NOW).map((x) => x.id)).toEqual(["h"]);
    expect(dueTasks([t("d", "  DAILY")], {}, NOW)[0]!.schedule).toBe("daily");
  });

  it("drops malformed items at the harness boundary (per-item shape guard) without crashing", () => {
    const dirty = [
      t("ok", "daily"),
      { id: "", text: "no id", schedule: "daily" },
      { id: "no-text", text: "", schedule: "daily" },
      null as unknown as OwnerTask,
      { id: 5 as unknown as string, text: "bad id type", schedule: "daily" },
    ];
    expect(dueTasks(dirty, {}, NOW).map((x) => x.id)).toEqual(["ok"]);
  });

  it("fails safe on a garbage clock: only never-run tasks are shown, no recurring task fires early", () => {
    const runs = { h: 500, d: 500 };
    expect(dueTasks([t("h", "hourly"), t("d", "daily")], runs, NaN)).toEqual([]);
    expect(dueTasks([t("new", "daily")], {}, NaN).map((x) => x.id)).toEqual(["new"]);
  });

  it("a null/garbage ledger is treated as empty -> every task reads never-run (safe: all shown)", () => {
    const tasks = [t("a", "daily"), t("b", "weekly")];
    expect(dueTasks(tasks, null, NOW).map((x) => x.id)).toEqual(["a", "b"]);
    expect(dueTasks(tasks, undefined, NOW).map((x) => x.id)).toEqual(["a", "b"]);
  });

  it("mixes due and not-due across a realistic playbook", () => {
    const playbook = [
      t("presence", "hourly"),
      t("mailbox", "hourly"),
      t("daily-post", "daily"),
      t("weekly-digest", "weekly"),
      t("say-hello", "once"),
    ];
    const runs = {
      presence: NOW - HOUR, // due
      mailbox: NOW - 600, // not due (10m ago)
      "daily-post": NOW - DAY, // due
      "weekly-digest": NOW - 3 * DAY, // not due
      "say-hello": NOW - WEEK, // once, ran -> never again
    };
    expect(dueTasks(playbook, runs, NOW).map((x) => x.id)).toEqual(["presence", "daily-post"]);
  });
});
