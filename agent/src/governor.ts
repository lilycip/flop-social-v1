import { DurableObject } from "cloudflare:workers";
import { canonInt } from "./shared/canon";
import { bytesToHex, hexToBytes } from "./shared/bytes";
import { isValidName } from "./shared/names";
import {
  authorizedCeiling,
  grantClass,
  verifyGrant,
  type Grant,
} from "./shared/grant";

export const Status = {
  OK: "OK",
  GATE_NOT_CONFIGURED: "GATE_NOT_CONFIGURED", // no owner/agent anchor set
  GATE_NOT_ACTIVE: "GATE_NOT_ACTIVE", // no active grant, or grant_id is not the pinned one
  GATE_REVOKED: "GATE_REVOKED",
  GATE_EXPIRED: "GATE_EXPIRED",
  GATE_NO_GRANT: "GATE_NO_GRANT", // signature/owner/agent verification failed
  GATE_CLASS: "GATE_CLASS", // action's class is not on the allowlist (or ceiling 0)
  GATE_CEILING: "GATE_CEILING", // daily counter already at the ceiling
  GATE_NONCE: "GATE_NONCE", // replay / rewind
  GATE_CLOCK: "GATE_CLOCK", // caller `now` is not a well-formed timestamp
  GATE_WINDOW: "GATE_WINDOW", // grant window is below the minimum (defense-in-depth floor)
  GATE_STEER: "GATE_STEER", // steer nonce is not strictly newer than the high-water
  ERROR_BAD_REQUEST: "ERROR_BAD_REQUEST", // malformed request shape
} as const;
export type StatusValue = (typeof Status)[keyof typeof Status];

const MIN_WINDOW_SEC = 600;

const ISSUED_SKEW_SEC = 300n;

interface GovernorEnv {
  TEST_MODE?: string;
}

export interface AuthorizeRequest {
  now: number;
  verb: string;
  target?: unknown;
  verdict?: unknown;
  boardMatch?: boolean;
  key: string;
  room: string;
  nonce: number | string;
}

export interface AuthorizeResult {
  status: StatusValue;
  klass?: string;
  windowStart?: number;
  counter?: number;
  ceiling?: number;
}

interface PinResult {
  status: StatusValue;
}

export class Governor extends DurableObject<GovernorEnv> {
  #sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: GovernorEnv) {
    super(ctx, env);
    this.#sql = ctx.storage.sql;
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
    this.#sql.exec(
      `CREATE TABLE IF NOT EXISTS counters (klass TEXT, window_start INTEGER, n INTEGER NOT NULL, PRIMARY KEY (klass, window_start))`,
    );
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS nonces (scope TEXT PRIMARY KEY, high TEXT NOT NULL)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS revoked (grant_id TEXT PRIMARY KEY)`);
    this.#sql.exec(`CREATE TABLE IF NOT EXISTS steer_seen (id INTEGER PRIMARY KEY, high TEXT NOT NULL)`);
  }

  #validNow(now: number): boolean {
    return Number.isInteger(now) && now >= 0;
  }

  #nowSec(callerNow: number): number {
    return this.env.TEST_MODE === "1" ? callerNow : Math.floor(Date.now() / 1000);
  }

  #metaGet(k: string): string | null {
    const rows = this.#sql.exec("SELECT v FROM meta WHERE k = ?", k).toArray();
    return rows.length ? (rows[0]!["v"] as string) : null;
  }

  #metaPut(k: string, v: string): void {
    this.#sql.exec(
      "INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
      k,
      v,
    );
  }

  #metaDel(k: string): void {
    this.#sql.exec("DELETE FROM meta WHERE k = ?", k);
  }

  #ownerPub(): Uint8Array | null {
    const hex = this.#metaGet("owner_pub");
    return hex ? hexToBytes(hex) : null;
  }

  #revokedSet(): Set<string> {
    const rows = this.#sql.exec("SELECT grant_id FROM revoked").toArray();
    return new Set(rows.map((r) => r["grant_id"] as string));
  }

  configure(input: { ownerPubHex?: string; agentDid?: string }): PinResult {
    const ownerPubHex = input?.ownerPubHex;
    const agentDid = input?.agentDid;
    if (typeof ownerPubHex !== "string" || typeof agentDid !== "string" || !agentDid) {
      return { status: Status.ERROR_BAD_REQUEST };
    }
    let pub: Uint8Array;
    try {
      pub = hexToBytes(ownerPubHex);
    } catch {
      return { status: Status.ERROR_BAD_REQUEST };
    }
    if (pub.length !== 32) return { status: Status.ERROR_BAD_REQUEST };
    const normHex = bytesToHex(pub);
    const curOwner = this.#metaGet("owner_pub");
    const curAgent = this.#metaGet("agent_did");
    if ((curOwner !== null && curOwner !== normHex) || (curAgent !== null && curAgent !== agentDid)) {
      return { status: Status.ERROR_BAD_REQUEST };
    }
    this.#metaPut("owner_pub", normHex);
    this.#metaPut("agent_did", agentDid);
    return { status: Status.OK };
  }

  async pinGrant(grant: Grant, now: number): Promise<PinResult> {
    const owner = this.#ownerPub();
    const agentDid = this.#metaGet("agent_did");
    if (owner === null || !agentDid) return { status: Status.GATE_NOT_CONFIGURED };
    if (typeof now !== "number" || !this.#validNow(now)) return { status: Status.ERROR_BAD_REQUEST };
    const t = this.#nowSec(now);
    const ok = await verifyGrant(owner, grant, t, this.#revokedSet(), agentDid);
    if (!ok) return { status: Status.GATE_NO_GRANT };
    try {
      if (Number(canonInt((grant as Grant).window, "window")) < MIN_WINDOW_SEC) {
        return { status: Status.GATE_WINDOW };
      }
      if (BigInt(canonInt((grant as Grant).issued, "issued")) > BigInt(t) + ISSUED_SKEW_SEC) {
        return { status: Status.GATE_NO_GRANT };
      }
    } catch {
      return { status: Status.GATE_NO_GRANT };
    }
    this.#metaPut("active_grant_id", (grant as Grant).grant_id);
    this.#metaPut("active_grant", JSON.stringify(grant));
    this.#advanceGrantHigh((grant as Grant).issued);
    return { status: Status.OK };
  }

  #grantHigh(): bigint {
    const hi = this.#metaGet("grant_issued_high");
    return hi ? BigInt(hi) : 0n;
  }

  #advanceGrantHigh(issued: number | string): void {
    let issuedCanon: string;
    try {
      issuedCanon = canonInt(issued, "issued");
    } catch {
      return;
    }
    if (BigInt(issuedCanon) > this.#grantHigh()) this.#metaPut("grant_issued_high", issuedCanon);
  }

  revoke(grantId: string): PinResult {
    if (typeof grantId !== "string" || !grantId) return { status: Status.ERROR_BAD_REQUEST };
    this.#sql.exec("INSERT OR IGNORE INTO revoked (grant_id) VALUES (?)", grantId);
    if (this.#metaGet("active_grant_id") === grantId) {
      this.#metaDel("active_grant_id");
      this.#metaDel("active_grant");
    }
    return { status: Status.OK };
  }

  steerGate(nonce: number | string): PinResult {
    let nonceCanon: string;
    try {
      nonceCanon = canonInt(nonce, "steer_nonce");
    } catch {
      return { status: Status.ERROR_BAD_REQUEST };
    }
    const rows = this.#sql.exec("SELECT high FROM steer_seen WHERE id = 1").toArray();
    const high = rows.length ? BigInt(rows[0]!["high"] as string) : 0n;
    if (BigInt(nonceCanon) <= high) return { status: Status.GATE_STEER };
    this.#sql.exec(
      "INSERT INTO steer_seen (id, high) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET high = excluded.high",
      nonceCanon,
    );
    return { status: Status.OK };
  }

  async #loadVerifiedActiveGrant(t: number): Promise<{ grant: Grant } | { gate: StatusValue }> {
    const owner = this.#ownerPub();
    const agentDid = this.#metaGet("agent_did");
    if (owner === null || !agentDid) return { gate: Status.GATE_NOT_CONFIGURED };
    const activeJson = this.#metaGet("active_grant");
    const activeId = this.#metaGet("active_grant_id");
    if (!activeJson || !activeId) return { gate: Status.GATE_NOT_ACTIVE };
    let grant: Grant;
    try {
      grant = JSON.parse(activeJson) as Grant;
    } catch {
      return { gate: Status.GATE_NOT_ACTIVE };
    }
    const revoked = this.#revokedSet();
    if (revoked.has(grant.grant_id)) return { gate: Status.GATE_REVOKED };
    try {
      if (BigInt(canonInt(grant.expiry, "expiry")) < BigInt(t)) return { gate: Status.GATE_EXPIRED };
    } catch {
      return { gate: Status.GATE_NO_GRANT };
    }
    if (!(await verifyGrant(owner, grant, t, revoked, agentDid))) return { gate: Status.GATE_NO_GRANT };
    return { grant };
  }

  async reserveModel(now: number): Promise<AuthorizeResult> {
    if (typeof now !== "number") return { status: Status.ERROR_BAD_REQUEST };
    if (!this.#validNow(now)) return { status: Status.GATE_CLOCK };
    const t = this.#nowSec(now);
    const loaded = await this.#loadVerifiedActiveGrant(t);
    if ("gate" in loaded) return { status: loaded.gate };
    const grant = loaded.grant;
    const ceiling = authorizedCeiling(grant, "MODEL");
    if (ceiling === null) return { status: Status.GATE_CLASS };
    let windowSecs: number;
    try {
      windowSecs = Number(canonInt(grant.window, "window"));
    } catch {
      return { status: Status.GATE_NO_GRANT };
    }
    if (windowSecs < MIN_WINDOW_SEC) return { status: Status.GATE_WINDOW };
    const windowStart = Math.floor(t / windowSecs) * windowSecs;

    if (this.#sql.exec("SELECT 1 FROM revoked WHERE grant_id = ?", grant.grant_id).toArray().length) {
      return { status: Status.GATE_REVOKED };
    }
    if (this.#metaGet("active_grant_id") !== grant.grant_id) return { status: Status.GATE_NOT_ACTIVE };
    const crows = this.#sql
      .exec("SELECT n FROM counters WHERE klass = 'MODEL' AND window_start = ?", windowStart)
      .toArray();
    const n = crows.length ? Number(crows[0]!["n"]) : 0;
    if (n >= ceiling) return { status: Status.GATE_CEILING };
    this.#sql.exec(
      "INSERT INTO counters (klass, window_start, n) VALUES ('MODEL', ?, 1) ON CONFLICT(klass, window_start) DO UPDATE SET n = n + 1",
      windowStart,
    );
    return { status: Status.OK, klass: "MODEL", windowStart, counter: n + 1, ceiling };
  }

  async applySteerGrant(grant: Grant, now: number): Promise<PinResult> {
    if (typeof now !== "number" || !this.#validNow(now)) return { status: Status.ERROR_BAD_REQUEST };
    const t = this.#nowSec(now);
    const owner = this.#ownerPub();
    const agentDid = this.#metaGet("agent_did");
    if (owner === null || !agentDid) return { status: Status.GATE_NOT_CONFIGURED };
    if (!(await verifyGrant(owner, grant, t, this.#revokedSet(), agentDid))) {
      return { status: Status.GATE_NO_GRANT };
    }
    let issuedCanon: string;
    try {
      issuedCanon = canonInt(grant.issued, "issued");
    } catch {
      return { status: Status.GATE_NO_GRANT };
    }
    if (BigInt(issuedCanon) > BigInt(t) + ISSUED_SKEW_SEC) return { status: Status.GATE_STEER };
    const isStop = !grant.allow || Object.keys(grant.allow).length === 0;
    if (!isStop) {
      try {
        if (Number(canonInt(grant.window, "window")) < MIN_WINDOW_SEC) return { status: Status.GATE_WINDOW };
      } catch {
        return { status: Status.GATE_NO_GRANT };
      }
    }

    if (BigInt(issuedCanon) <= this.#grantHigh()) return { status: Status.GATE_STEER };
    this.#metaPut("grant_issued_high", issuedCanon);
    this.#metaPut("active_grant_id", grant.grant_id);
    this.#metaPut("active_grant", JSON.stringify(grant));
    this.#metaPut("last_applied_issued", issuedCanon);
    return { status: Status.OK };
  }

  async authorize(req: AuthorizeRequest): Promise<AuthorizeResult> {
    if (req === null || typeof req !== "object") return { status: Status.ERROR_BAD_REQUEST };
    const { now, verb, target, verdict, boardMatch, key, room, nonce } = req;
    if (typeof now !== "number") return { status: Status.ERROR_BAD_REQUEST };
    if (!this.#validNow(now)) return { status: Status.GATE_CLOCK };
    const t = this.#nowSec(now);
    if (typeof verb !== "string" || !verb) return { status: Status.ERROR_BAD_REQUEST };
    if (!isValidName(key) || !isValidName(room)) return { status: Status.ERROR_BAD_REQUEST };
    let nonceCanon: string;
    try {
      nonceCanon = canonInt(nonce, "nonce");
    } catch {
      return { status: Status.ERROR_BAD_REQUEST };
    }

    const owner = this.#ownerPub();
    const agentDid = this.#metaGet("agent_did");
    if (owner === null || !agentDid) return { status: Status.GATE_NOT_CONFIGURED };

    const activeJson = this.#metaGet("active_grant");
    const activeId = this.#metaGet("active_grant_id");
    if (!activeJson || !activeId) return { status: Status.GATE_NOT_ACTIVE };
    let grant: Grant;
    try {
      grant = JSON.parse(activeJson) as Grant;
    } catch {
      return { status: Status.GATE_NOT_ACTIVE };
    }

    const revoked = this.#revokedSet();
    if (revoked.has(grant.grant_id)) return { status: Status.GATE_REVOKED };
    try {
      if (BigInt(canonInt(grant.expiry, "expiry")) < BigInt(t)) return { status: Status.GATE_EXPIRED };
    } catch {
      return { status: Status.GATE_NO_GRANT };
    }
    const ok = await verifyGrant(owner, grant, t, revoked, agentDid);
    if (!ok) return { status: Status.GATE_NO_GRANT };

    let klass: string;
    try {
      klass = grantClass(verb, target, verdict, boardMatch ?? false);
    } catch {
      return { status: Status.GATE_CLASS };
    }
    const ceiling = authorizedCeiling(grant, klass);
    if (ceiling === null) return { status: Status.GATE_CLASS };

    let windowSecs: number;
    try {
      windowSecs = Number(canonInt(grant.window, "window"));
    } catch {
      return { status: Status.GATE_NO_GRANT };
    }
    if (windowSecs < MIN_WINDOW_SEC) return { status: Status.GATE_WINDOW };
    const windowStart = Math.floor(t / windowSecs) * windowSecs;

    return this.#reserveSync(grant.grant_id, klass, windowStart, ceiling, key, room, nonceCanon);
  }

  #reserveSync(
    grantId: string,
    klass: string,
    windowStart: number,
    ceiling: number,
    key: string,
    room: string,
    nonceCanon: string,
  ): AuthorizeResult {
    if (this.#sql.exec("SELECT 1 FROM revoked WHERE grant_id = ?", grantId).toArray().length) {
      return { status: Status.GATE_REVOKED };
    }
    if (this.#metaGet("active_grant_id") !== grantId) return { status: Status.GATE_NOT_ACTIVE };

    const scope = `${key}|${room}`;
    const nrows = this.#sql.exec("SELECT high FROM nonces WHERE scope = ?", scope).toArray();
    const high = nrows.length ? BigInt(nrows[0]!["high"] as string) : 0n;
    if (BigInt(nonceCanon) <= high) return { status: Status.GATE_NONCE };

    const crows = this.#sql
      .exec("SELECT n FROM counters WHERE klass = ? AND window_start = ?", klass, windowStart)
      .toArray();
    const n = crows.length ? Number(crows[0]!["n"]) : 0;
    if (n >= ceiling) return { status: Status.GATE_CEILING };

    this.#sql.exec(
      "INSERT INTO counters (klass, window_start, n) VALUES (?, ?, 1) ON CONFLICT(klass, window_start) DO UPDATE SET n = n + 1",
      klass,
      windowStart,
    );
    this.#sql.exec(
      "INSERT INTO nonces (scope, high) VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET high = excluded.high",
      scope,
      nonceCanon,
    );
    return { status: Status.OK, klass, windowStart, counter: n + 1, ceiling };
  }

  snapshot(): {
    configured: boolean;
    activeGrantId: string | null;
    counters: Array<{ klass: string; windowStart: number; n: number }>;
    revoked: string[];
    lastAppliedIssued: string | null;
    grantHigh: string | null;
  } {
    const configured = this.#metaGet("owner_pub") !== null && this.#metaGet("agent_did") !== null;
    const counters = this.#sql
      .exec("SELECT klass, window_start, n FROM counters ORDER BY klass, window_start")
      .toArray()
      .map((r) => ({ klass: r["klass"] as string, windowStart: Number(r["window_start"]), n: Number(r["n"]) }));
    return {
      configured,
      activeGrantId: this.#metaGet("active_grant_id"),
      counters,
      revoked: [...this.#revokedSet()],
      lastAppliedIssued: this.#metaGet("last_applied_issued"),
      grantHigh: this.#metaGet("grant_issued_high"),
    };
  }
}
