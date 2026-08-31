import { asTarget, useful } from "./action";
import { canonInt } from "./canon";
import { pubRawEquals, verifyB64url } from "./did";
import { isValidName } from "./names";
import { utf8 } from "./bytes";

const KLASS_RE = /^[A-Za-z0-9:_-]{1,64}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export const DEFAULT_WINDOW_SECONDS = 86400;

export const DANGEROUS_CLASSES: ReadonlySet<string> = new Set([
  "ATTEST:useful:no-board-match",
  "NOTE_WRITE:identity",
  "NOTE_WRITE:ownership",
]);

export interface Grant {
  grant_id: string;
  owner_did: string;
  agent_did: string;
  issued: number | string;
  expiry: number | string;
  window: number | string;
  allow: Record<string, number | string>;
  signature: string;
}

export function isDangerous(klass: unknown): boolean {
  if (typeof klass !== "string") return true;
  return DANGEROUS_CLASSES.has(klass) || klass.startsWith("OTHER:") || klass.endsWith(":unknown");
}

export function grantClass(
  verb: string,
  target?: unknown,
  verdict?: unknown,
  boardMatch = false,
): string {
  const v = (verb || "").toUpperCase();
  const t = asTarget(target);
  if (v === "ATTEST") {
    if (useful(verdict)) {
      return boardMatch ? "ATTEST:useful:board-match" : "ATTEST:useful:no-board-match";
    }
    return "ATTEST:not";
  }
  if (v === "SAY") return "SAY";
  if (v === "NOTE_WRITE") {
    const ns = (t["namespace"] as string) || "";
    if (!isValidName(ns)) return "NOTE_WRITE:unknown";
    if (ns === "did" || ns.startsWith("did-")) return "NOTE_WRITE:identity";
    if (ns === "room-owners" || ns === "room-allow") return "NOTE_WRITE:ownership";
    return "NOTE_WRITE:note";
  }
  if (v === "RESULT") return "RESULT";
  if (v === "CLAIM") return "CLAIM";
  return "OTHER:" + (v || "UNKNOWN");
}

function canonAllow(allow: Record<string, number | string>): string {
  if (allow === null || typeof allow !== "object" || Array.isArray(allow)) {
    throw new Error("allow must be a dict of {klass: ceiling}");
  }
  const parts: string[] = [];
  for (const k of Object.keys(allow).sort()) {
    if (!KLASS_RE.test(k)) throw new Error(`bad class name: ${JSON.stringify(k)}`);
    parts.push(`${k}=${canonInt(allow[k]!, "ceiling")}`);
  }
  return parts.join(",");
}

export function grantMessage(
  grantId: string,
  ownerDid: string,
  agentDid: string,
  issued: number | string,
  expiry: number | string,
  window: number | string,
  allow: Record<string, number | string>,
): Uint8Array {
  if (typeof grantId !== "string" || !ID_RE.test(grantId)) {
    throw new Error(`grant_id must match ${ID_RE.source}`);
  }
  if (typeof agentDid !== "string" || !agentDid) {
    throw new Error("agent_did must be a non-empty did:key string");
  }
  const s =
    `grant|${grantId}|${ownerDid}|agent:${agentDid}` +
    `|issued:${canonInt(issued, "issued")}|exp:${canonInt(expiry, "expiry")}` +
    `|window:${canonInt(window, "window")}|allow:${canonAllow(allow)}`;
  return utf8(s);
}

export async function verifyGrant(
  ownerPub: Uint8Array | null,
  grant: unknown,
  now: number | null,
  revokedIds: ReadonlySet<string> | null,
  expectedAgent: string,
): Promise<boolean> {
  if (grant === null || typeof grant !== "object" || Array.isArray(grant)) return false;
  if (ownerPub === null || now === null || revokedIds === null || !expectedAgent) return false;
  const g = grant as Partial<Grant>;
  const sig = g.signature;
  const ownerDid = g.owner_did;
  const grantId = g.grant_id;
  const agentDid = g.agent_did;
  if (!sig || !ownerDid || !grantId || !agentDid) return false;
  if (agentDid !== expectedAgent) return false;
  if (!pubRawEquals(ownerDid, ownerPub)) return false;
  if (revokedIds.has(grantId)) return false;
  let msg: Uint8Array;
  try {
    if (BigInt(canonInt(g.expiry as number | string, "expiry")) < BigInt(Math.trunc(now))) return false;
    msg = grantMessage(grantId, ownerDid, agentDid, g.issued!, g.expiry!, g.window!, g.allow || {});
  } catch {
    return false;
  }
  return verifyB64url(ownerPub, sig, msg);
}

export function authorizedCeiling(grant: Grant, klass: string): number | null {
  const a = grant.allow || {};
  const c = a[klass];
  if (c === undefined || c === null) return null;
  let v: number;
  try {
    v = Number(canonInt(c, "ceiling"));
  } catch {
    return null;
  }
  return v > 0 ? v : null;
}

export async function autoCeiling(
  ownerPub: Uint8Array | null,
  grant: unknown,
  verb: string,
  target: unknown,
  verdict: unknown,
  boardMatch: boolean,
  now: number | null,
  revokedIds: ReadonlySet<string> | null,
  expectedAgent: string,
): Promise<number | null> {
  if (!(await verifyGrant(ownerPub, grant, now, revokedIds, expectedAgent))) return null;
  let klass: string;
  try {
    klass = grantClass(verb, target, verdict, boardMatch);
  } catch {
    return null;
  }
  return authorizedCeiling(grant as Grant, klass);
}
