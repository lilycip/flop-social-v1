import { isValidName } from "./names";
import { sha256Hex } from "./bytes";

export const VERSION = "v2";
export const KNOWN_VERBS = ["ATTEST", "RESULT", "CLAIM", "NOTE_WRITE", "SAY"] as const;

export type Target = Record<string, unknown>;
export type Verdict = Record<string, unknown>;

export function asTarget(target: unknown): Target {
  if (target === null || target === undefined) return {};
  if (typeof target !== "object" || Array.isArray(target)) {
    throw new Error("target must be a dict");
  }
  return target as Target;
}

export function asVerdict(verdict: unknown): Verdict {
  if (verdict === null || verdict === undefined) return {};
  if (typeof verdict !== "object" || Array.isArray(verdict)) {
    throw new Error("verdict must be a dict");
  }
  return verdict as Verdict;
}

export function useful(verdict: unknown): boolean {
  const u = asVerdict(verdict)["useful"];
  if (typeof u !== "boolean") {
    throw new Error("ATTEST verdict.useful must be a real boolean");
  }
  return u;
}

const HEX = new Set("0123456789abcdef");

export function isSha256Hex(h: unknown): h is string {
  return typeof h === "string" && h.length === 64 && [...h].every((c) => HEX.has(c));
}

function tok(label: string, value: unknown): string {
  if (!isValidName(value)) {
    throw new Error(`${label} must match the name grammar ^[a-z0-9][a-z0-9_-]{0,47}$`);
  }
  return value;
}

function rh(label: string, value: unknown): string {
  if (!isSha256Hex(value)) throw new Error(`${label} must be a 64-char lowercase sha256 hex`);
  return value;
}

function requireStr(label: string, value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

async function contentHash(label: string, value: unknown): Promise<string> {
  return sha256Hex(requireStr(label, value));
}

export async function actionString(verb: string, target: unknown, verdict?: unknown): Promise<string> {
  const v = (verb || "").toUpperCase();
  const t = asTarget(target);

  if (v === "ATTEST") {
    const job = tok("job_id", t["job_id"]);
    const vv = useful(verdict) ? "useful" : "not";
    const r = rh("result_hash", t["result_hash"]);
    return `ATTEST ${VERSION} | job:${job} | verdict:${vv} | rh:${r}`;
  }
  if (v === "RESULT") {
    const job = tok("job_id", t["job_id"]);
    const r =
      t["result_hash"] !== null && t["result_hash"] !== undefined
        ? rh("result_hash", t["result_hash"])
        : await contentHash("result", t["result"]);
    return `RESULT ${VERSION} | job:${job} | rh:${r}`;
  }
  if (v === "CLAIM") {
    const job = tok("job_id", t["job_id"]);
    return `CLAIM ${VERSION} | job:${job}`;
  }
  if (v === "NOTE_WRITE") {
    const ns = tok("namespace", t["namespace"]);
    const key = tok("key", t["key"]);
    const vh = await contentHash("value", t["value"]);
    return `NOTE_WRITE ${VERSION} | ns:${ns} | key:${key} | vh:${vh}`;
  }
  if (v === "SAY") {
    const room = tok("room", t["room"]);
    const th = await contentHash("text", t["text"]);
    return `SAY ${VERSION} | room:${room} | th:${th}`;
  }
  throw new Error(`unknown verb ${JSON.stringify(verb)}: refusing to build an under-bound action`);
}

export function embeddedDestination(verb: string, target: unknown): string | null {
  const v = (verb || "").toUpperCase();
  const t = asTarget(target);
  if (v === "SAY") return (t["room"] as string) ?? null;
  if (v === "NOTE_WRITE") return (t["namespace"] as string) ?? null;
  return null;
}

export async function resultHashOf(body: unknown): Promise<string> {
  return contentHash("body", body);
}
