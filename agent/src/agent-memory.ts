import { DurableObject } from "cloudflare:workers";

const MAX_LEARNINGS = 256;
const MAX_LEARNING_LEN = 512;
const LEARNING_TTL_SEC = 1_209_600;
const MAX_ACTED = 512;
const MAX_ACTION_LEN = 64;
const MAX_SEEN = 2048;
const MAX_ID_LEN = 128;
const MAX_GET = 256;
const MAX_HANDOFF_LEN = 1024;
const MAX_TASK_RUNS = 64;
const MAX_TASK_ID_LEN = 128;
const MAX_RECENT = 32;
const MAX_RECENT_LEN = 200;
const RECENT_TTL_SEC = 86_400;

interface MemoryEnv {
  TEST_MODE?: string;
}

export interface Learning {
  text: string;
  created: number;
}
export interface MemorySnapshot {
  learnings: number;
  acted: number;
  seen: number;
  recent: number;
}

export class AgentMemory extends DurableObject<MemoryEnv> {
  #sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: MemoryEnv) {
    super(ctx, env);
    this.#sql = ctx.storage.sql;
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS learnings (text TEXT PRIMARY KEY, created INTEGER NOT NULL, expiry INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS acted (job_id TEXT NOT NULL, action TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (job_id, action))`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS seen (job_id TEXT PRIMARY KEY, created INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS handoff (id INTEGER PRIMARY KEY, text TEXT NOT NULL, updated INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS task_runs (task_id TEXT PRIMARY KEY, last_run INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS recent (text TEXT PRIMARY KEY, created INTEGER NOT NULL, expiry INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS last_think (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS flags (k TEXT PRIMARY KEY, v INTEGER NOT NULL)`);
  }

  // A DURABLE, non-evictable 'have I introduced myself' bit. `recent` is a 32-entry FIFO with a 24h TTL,
  // so the introduction (the OLDEST entry) scrolls out after a few busy wakes and the agent would
  // re-introduce itself in public. This flag never evicts, so introduce-once holds for the life of the
  // identity.
  getIntroduced(): boolean {
    const rows = this.#sql.exec("SELECT v FROM flags WHERE k = 'introduced'").toArray();
    return rows.length ? Number((rows[0] as { v: unknown }).v) === 1 : false;
  }

  setIntroduced(): { stored: boolean } {
    this.#sql.exec("INSERT OR REPLACE INTO flags (k, v) VALUES ('introduced', 1)");
    return { stored: true };
  }

  #now(callerNow?: number): number {
    if (this.env.TEST_MODE === "1" && typeof callerNow === "number" && Number.isFinite(callerNow)) {
      return Math.floor(callerNow);
    }
    return Math.floor(Date.now() / 1000);
  }

  #clip(v: unknown, cap: number): string | null {
    if (typeof v !== "string") return null;
    const t = v.trim();
    return t.length === 0 ? null : t.slice(0, cap);
  }

  #count(table: "learnings" | "acted" | "seen" | "recent"): number {
    const q =
      table === "learnings"
        ? "SELECT COUNT(*) AS c FROM learnings"
        : table === "acted"
          ? "SELECT COUNT(*) AS c FROM acted"
          : table === "seen"
            ? "SELECT COUNT(*) AS c FROM seen"
            : "SELECT COUNT(*) AS c FROM recent";
    return (this.#sql.exec(q).toArray()[0] as { c: number }).c;
  }

  putLearning(text: unknown, callerNow?: number): { stored: boolean } {
    const t = this.#clip(text, MAX_LEARNING_LEN);
    if (t === null) return { stored: false };
    const now = this.#now(callerNow);
    this.#sql.exec("DELETE FROM learnings WHERE expiry <= ?", now);
    const existed = this.#sql.exec("SELECT 1 FROM learnings WHERE text = ?", t).toArray().length > 0;
    if (existed) return { stored: false };
    this.#sql.exec("INSERT INTO learnings (text, created, expiry) VALUES (?, ?, ?)", t, now, now + LEARNING_TTL_SEC);
    const over = this.#count("learnings") - MAX_LEARNINGS;
    if (over > 0) {
      this.#sql.exec("DELETE FROM learnings WHERE text IN (SELECT text FROM learnings ORDER BY created ASC, rowid ASC LIMIT ?)", over);
    }
    return { stored: true };
  }

  getLearnings(callerNow?: number): Learning[] {
    const now = this.#now(callerNow);
    this.#sql.exec("DELETE FROM learnings WHERE expiry <= ?", now);
    return this.#sql
      .exec("SELECT text, created FROM learnings ORDER BY created DESC LIMIT ?", MAX_GET)
      .toArray()
      .map((r) => ({ text: String((r as { text: unknown }).text), created: Number((r as { created: unknown }).created) }));
  }

  recordActed(jobId: unknown, action: unknown, callerNow?: number): { stored: boolean } {
    const id = this.#clip(jobId, MAX_ID_LEN);
    const act = this.#clip(action, MAX_ACTION_LEN);
    if (id === null || act === null) return { stored: false };
    const now = this.#now(callerNow);
    const existed = this.#sql.exec("SELECT 1 FROM acted WHERE job_id = ? AND action = ?", id, act).toArray().length > 0;
    if (existed) return { stored: false };
    this.#sql.exec("INSERT INTO acted (job_id, action, created) VALUES (?, ?, ?)", id, act, now);
    const over = this.#count("acted") - MAX_ACTED;
    if (over > 0) {
      this.#sql.exec("DELETE FROM acted WHERE rowid IN (SELECT rowid FROM acted ORDER BY created ASC, rowid ASC LIMIT ?)", over);
    }
    return { stored: true };
  }

  hasActed(jobId: unknown, action: unknown): boolean {
    const id = this.#clip(jobId, MAX_ID_LEN);
    const act = this.#clip(action, MAX_ACTION_LEN);
    if (id === null || act === null) return false;
    return this.#sql.exec("SELECT 1 FROM acted WHERE job_id = ? AND action = ?", id, act).toArray().length > 0;
  }

  markSeen(jobIds: unknown, callerNow?: number): { fresh: string[] } {
    const now = this.#now(callerNow);
    const arr = Array.isArray(jobIds) ? jobIds : [];
    const fresh: string[] = [];
    for (const raw of arr.slice(0, MAX_GET)) {
      const id = this.#clip(raw, MAX_ID_LEN);
      if (id === null) continue;
      const existed = this.#sql.exec("SELECT 1 FROM seen WHERE job_id = ?", id).toArray().length > 0;
      if (existed) continue;
      this.#sql.exec("INSERT INTO seen (job_id, created) VALUES (?, ?)", id, now);
      fresh.push(id);
    }
    const over = this.#count("seen") - MAX_SEEN;
    if (over > 0) {
      this.#sql.exec("DELETE FROM seen WHERE job_id IN (SELECT job_id FROM seen ORDER BY created ASC LIMIT ?)", over);
    }
    return { fresh };
  }

  setHandoff(text: unknown, callerNow?: number): { stored: boolean } {
    const now = this.#now(callerNow);
    const t = this.#clip(text, MAX_HANDOFF_LEN);
    if (t === null) {
      this.#sql.exec("DELETE FROM handoff WHERE id = 1");
      return { stored: false };
    }
    this.#sql.exec("INSERT OR REPLACE INTO handoff (id, text, updated) VALUES (1, ?, ?)", t, now);
    return { stored: true };
  }

  getHandoff(): string | null {
    const rows = this.#sql.exec("SELECT text FROM handoff WHERE id = 1").toArray();
    return rows.length ? String((rows[0] as { text: unknown }).text) : null;
  }

  setLastThink(nowMs: unknown): { stored: boolean } {
    const t = typeof nowMs === "number" && Number.isFinite(nowMs) && nowMs > 0 ? Math.floor(nowMs) : 0;
    if (t <= 0) return { stored: false };
    this.#sql.exec("INSERT OR REPLACE INTO last_think (id, ts) VALUES (1, ?)", t);
    return { stored: true };
  }

  getLastThink(): number {
    const rows = this.#sql.exec("SELECT ts FROM last_think WHERE id = 1").toArray();
    if (!rows.length) return 0;
    const v = Number((rows[0] as { ts: unknown }).ts);
    return Number.isFinite(v) && v > 0 ? v : 0;
  }

  #countTaskRuns(): number {
    return (this.#sql.exec("SELECT COUNT(*) AS c FROM task_runs").toArray()[0] as { c: number }).c;
  }

  recordTaskRun(taskId: unknown, callerNow?: number): { stored: boolean } {
    const id = this.#clip(taskId, MAX_TASK_ID_LEN);
    if (id === null) return { stored: false };
    const now = this.#now(callerNow);
    this.#sql.exec("INSERT OR REPLACE INTO task_runs (task_id, last_run) VALUES (?, ?)", id, now);
    const over = this.#countTaskRuns() - MAX_TASK_RUNS;
    if (over > 0) {
      this.#sql.exec("DELETE FROM task_runs WHERE task_id IN (SELECT task_id FROM task_runs ORDER BY last_run ASC, rowid ASC LIMIT ?)", over);
    }
    return { stored: true };
  }

  getTaskRuns(): Record<string, number> {
    const rows = this.#sql.exec("SELECT task_id, last_run FROM task_runs ORDER BY last_run DESC LIMIT ?", MAX_TASK_RUNS).toArray();
    const out: Record<string, number> = {};
    for (const r of rows) {
      const rec = r as { task_id: unknown; last_run: unknown };
      out[String(rec.task_id)] = Number(rec.last_run);
    }
    return out;
  }

  recordRecent(text: unknown, callerNow?: number): { stored: boolean } {
    const t = this.#clip(text, MAX_RECENT_LEN);
    if (t === null) return { stored: false };
    const now = this.#now(callerNow);
    this.#sql.exec("DELETE FROM recent WHERE expiry <= ?", now);
    const existed = this.#sql.exec("SELECT 1 FROM recent WHERE text = ?", t).toArray().length > 0;
    if (existed) return { stored: false };
    this.#sql.exec("INSERT INTO recent (text, created, expiry) VALUES (?, ?, ?)", t, now, now + RECENT_TTL_SEC);
    const over = this.#count("recent") - MAX_RECENT;
    if (over > 0) {
      this.#sql.exec("DELETE FROM recent WHERE text IN (SELECT text FROM recent ORDER BY created ASC, rowid ASC LIMIT ?)", over);
    }
    return { stored: true };
  }

  getRecent(callerNow?: number): string[] {
    const now = this.#now(callerNow);
    this.#sql.exec("DELETE FROM recent WHERE expiry <= ?", now);
    return this.#sql
      .exec("SELECT text FROM recent ORDER BY created DESC LIMIT ?", MAX_RECENT)
      .toArray()
      .map((r) => String((r as { text: unknown }).text));
  }

  snapshot(): MemorySnapshot {
    return { learnings: this.#count("learnings"), acted: this.#count("acted"), seen: this.#count("seen"), recent: this.#count("recent") };
  }
}
