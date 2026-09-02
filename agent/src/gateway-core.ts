import { actionString, isSha256Hex } from "./shared/action";
import { canonInt } from "./shared/canon";
import { signB64url } from "./shared/did";
import { isValidName } from "./shared/names";
import { messageSigInput, noteSigInput, singleLine } from "./shared/protocol";
import type { AuthorizeRequest, AuthorizeResult, StatusValue } from "./governor";

export const KIBBLE_ROOM = "kibble";

export const SignStatus = {
  OK: "OK",
  GATE_SHAPE: "GATE_SHAPE", // not one of the two shapes, or a disallowed verb (e.g. SAY)
  GATE_INVALID: "GATE_INVALID", // the action could not be built from the given fields
  GATE_FORBIDDEN: "GATE_FORBIDDEN", // a give-away namespace (room-owners/room-allow/d-)
  GATE_INTERNAL: "GATE_INTERNAL", // unexpected internal error (never echoes anything)
  GATE_DUP: "GATE_DUP", // harness-side: an identical emit already went out this wake; not re-posted
} as const;
export type SignStatusValue = (typeof SignStatus)[keyof typeof SignStatus] | StatusValue;

export interface GovernorLike {
  authorize(req: AuthorizeRequest): Promise<AuthorizeResult>;
  reserveModel(now: number): Promise<AuthorizeResult>;
  applySteerGrant(grant: unknown, now: number): Promise<{ status: string }>;
  // True only when a verified, unexpired, un-revoked, NON-empty-allow grant is active. A STOP (empty
  // allow) or no grant returns false, so callers can make STOP mean dark without consuming any counter.
  hasLiveGrant(now: number): Promise<boolean>;
}

export interface GatewayCtx {
  signingKey: CryptoKey;
  ourDid: string;
  noteNs: string;
  noteKey: string;
  keyScope: string;
  governor: GovernorLike;
  boardReader: (jobId: string) => Promise<string | null>;
  now: () => number;
}

export type SignRequest =
  | {
      shape: "kibble";
      verb: "CLAIM" | "RESULT" | "ATTEST";
      target: Record<string, unknown>;
      verdict?: { useful: boolean };
      nonce: number | string;
    }
  | { shape: "note"; value: string; nonce: number | string }
  | { shape: "say"; room: string; text: string; nonce: number | string };

export type SignResult =
  | {
      status: "OK";
      shape: "kibble" | "note" | "say";
      did: string;
      signature: string;
      nonce: string;
      room?: string;
      text?: string;
      namespace?: string;
      key?: string;
      value?: string;
      boardMatch?: boolean;
    }
  | { status: Exclude<SignStatusValue, "OK"> };

const KIBBLE_VERBS = new Set(["CLAIM", "RESULT", "ATTEST"]);

export function isForbiddenNamespace(ns: string): boolean {
  return ns === "room-owners" || ns === "room-allow" || ns.startsWith("d-");
}

const RESERVED_SAY_ROOMS = new Set(["room-owners", "room-allow", "room-nonce", "did"]);
// A say into these rooms is refused: a signed say and a kibble work line share the same signing
// input, so a say into the kibble room (or a did- note room) would forge a non-say shape. Any room
// the gateway signs a non-say shape into must be reserved for say alone.
export function isReservedSayRoom(room: string): boolean {
  return room === KIBBLE_ROOM || RESERVED_SAY_ROOMS.has(room) || room.startsWith("did-");
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

async function signSay(
  req: Extract<SignRequest, { shape: "say" }>,
  ctx: GatewayCtx,
): Promise<SignResult> {
  const room = req.room;
  const text = req.text;
  if (!isValidName(room)) return { status: SignStatus.GATE_INVALID };
  if (isReservedSayRoom(room)) return { status: SignStatus.GATE_FORBIDDEN };
  if (typeof text !== "string" || hasLoneSurrogate(text)) {
    return { status: SignStatus.GATE_INVALID };
  }

  const gov = await ctx.governor.authorize({
    now: ctx.now(),
    verb: "SAY",
    target: { room, text },
    key: ctx.keyScope,
    room,
    nonce: req.nonce,
  });
  if (gov.status !== "OK") return { status: gov.status };

  const nonceCanon = canonInt(req.nonce, "nonce");
  const swept = singleLine(text);
  const sig = await signB64url(ctx.signingKey, messageSigInput(room, nonceCanon, swept));
  return { status: "OK", shape: "say", did: ctx.ourDid, signature: sig, nonce: nonceCanon, room, text: swept };
}

export async function gatewaySign(req: SignRequest, ctx: GatewayCtx): Promise<SignResult> {
  try {
    if (req === null || typeof req !== "object") return { status: SignStatus.GATE_SHAPE };
    if (req.shape === "kibble") return await signKibble(req, ctx);
    if (req.shape === "note") return await signNote(req, ctx);
    if (req.shape === "say") return await signSay(req, ctx);
    return { status: SignStatus.GATE_SHAPE };
  } catch {
    return { status: SignStatus.GATE_INTERNAL };
  }
}

async function signKibble(
  req: Extract<SignRequest, { shape: "kibble" }>,
  ctx: GatewayCtx,
): Promise<SignResult> {
  const verb = String(req.verb || "").toUpperCase();
  if (!KIBBLE_VERBS.has(verb)) return { status: SignStatus.GATE_SHAPE };

  const rt = (req.target ?? {}) as Record<string, unknown>;
  const target: Record<string, unknown> = {
    job_id: rt["job_id"],
    result_hash: rt["result_hash"],
    result: rt["result"],
  };
  const verdict = req.verdict == null ? undefined : { useful: (req.verdict as { useful?: unknown }).useful };

  let line: string;
  try {
    line = await actionString(verb, target, verdict);
  } catch {
    return { status: SignStatus.GATE_INVALID };
  }

  let boardMatch = false;
  if (verb === "ATTEST") {
    boardMatch = await deriveBoardMatch(target, ctx.boardReader);
  }

  const gov = await ctx.governor.authorize({
    now: ctx.now(),
    verb,
    target,
    verdict,
    boardMatch,
    key: ctx.keyScope,
    room: KIBBLE_ROOM,
    nonce: req.nonce,
  });
  if (gov.status !== "OK") return { status: gov.status };

  const nonceCanon = canonInt(req.nonce, "nonce");
  const swept = singleLine(line);
  const sig = await signB64url(ctx.signingKey, messageSigInput(KIBBLE_ROOM, nonceCanon, swept));
  return {
    status: "OK",
    shape: "kibble",
    did: ctx.ourDid,
    signature: sig,
    nonce: nonceCanon,
    room: KIBBLE_ROOM,
    text: swept,
    boardMatch,
  };
}

async function signNote(
  req: Extract<SignRequest, { shape: "note" }>,
  ctx: GatewayCtx,
): Promise<SignResult> {
  const ns = ctx.noteNs;
  const key = ctx.noteKey;
  const value = req.value;
  if (isForbiddenNamespace(ns) || !ns.startsWith("did-") || !isValidName(ns) || !isValidName(key)) {
    return { status: SignStatus.GATE_FORBIDDEN };
  }
  if (typeof value !== "string" || hasLoneSurrogate(value)) {
    return { status: SignStatus.GATE_INVALID };
  }

  const gov = await ctx.governor.authorize({
    now: ctx.now(),
    verb: "NOTE_WRITE",
    target: { namespace: ns, key, value },
    key: ctx.keyScope,
    room: ns,
    nonce: req.nonce,
  });
  if (gov.status !== "OK") return { status: gov.status };

  const nonceCanon = canonInt(req.nonce, "nonce");
  const sig = await signB64url(ctx.signingKey, noteSigInput(ns, key, nonceCanon, value));
  return {
    status: "OK",
    shape: "note",
    did: ctx.ourDid,
    signature: sig,
    nonce: nonceCanon,
    namespace: ns,
    key,
    value,
  };
}

async function deriveBoardMatch(
  target: Record<string, unknown>,
  boardReader: (jobId: string) => Promise<string | null>,
): Promise<boolean> {
  const jobId = target["job_id"];
  const rh = target["result_hash"];
  if (!isValidName(jobId) || !isSha256Hex(rh)) return false;
  let posted: string | null;
  try {
    posted = await boardReader(jobId);
  } catch {
    return false;
  }
  return isSha256Hex(posted) && posted === rh;
}
