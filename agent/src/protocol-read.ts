import { urlRoomRead, urlNoteGet, urlRoomsList, TECHNOCORE_BASE, KIBBLE_BASE } from "./shared/protocol";
import { isValidName, roomClass, nameIsBearerSecret } from "./shared/names";
import { sha256Hex } from "./shared/bytes";

const MAX_MESSAGES = 200;
const MAX_JOBS = 200;
const MAX_ROOMS = 64;
const MAX_ROOM_SCAN = MAX_ROOMS * 8;
const MAX_TEXT = 4096;
const MAX_ID = 128;
const MAX_BYTES = 2_000_000;

const CATEGORIES = new Set(["explain", "research", "review", "build", "coordinate"]);
const STATUSES = new Set(["open", "claimed", "delivered", "attested", "rejected"]);

function s(v: unknown, cap: number = MAX_TEXT): string {
  return typeof v === "string" ? v.slice(0, cap) : "";
}
function i(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) ? v : null;
}
function nn(v: unknown): number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : 0;
}
// The board's advertised result-hash prefix: 8 to 64 lowercase hex chars. Not a full hash; it anchors the
// verification in resolveResultHashes. Anything else (uppercase, wrong length, non-hex) is not usable.
function hexPrefix(v: unknown): string {
  return typeof v === "string" && /^[0-9a-f]{8,64}$/.test(v) ? v : "";
}

export interface RoomMessage {
  seq: number | null;
  ts: string | null;
  from: string;
  text: string;
  nonce: string | null;
  fromIsDidShaped: boolean;
}
export interface RoomRead {
  room: string;
  messages: RoomMessage[];
  lastSeq: number | null;
}
export interface ListedRoom {
  room: string;
  kind: string;
  topic: string | null;
  lastSeq: number | null;
}
export interface BoardJob {
  job_id: string;
  category: string;
  title: string;
  body: string;
  status: string;
  poster_did: string;
  worker_did: string;
  useful_n: number;
  not_n: number;
  seq: number | null;
  // The delivered result and its board-posted hash. Empty when the job has no delivery. The hash is what
  // an ATTEST must carry to board-match, so it is surfaced to the agent (fenced as untrusted like the body).
  result: string;
  result_hash: string;
}
export interface BoardRead {
  jobs: BoardJob[];
  stats: Record<string, unknown>;
}

export type JsonResult = { status: number; obj: unknown | null };
export type TextResult = { status: number; text: string | null };

export async function getText(fetchImpl: typeof fetch, url: string): Promise<TextResult> {
  try {
    const resp = await fetchImpl(url, { method: "GET", redirect: "manual", headers: { accept: "application/json" } });
    if (resp.status < 200 || resp.status >= 300) return { status: resp.status, text: null };
    const clen = resp.headers.get("content-length");
    if (clen !== null && Number(clen) > MAX_BYTES) return { status: resp.status, text: null };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_BYTES) return { status: resp.status, text: null };
    return { status: resp.status, text: new TextDecoder("utf-8", { fatal: false, ignoreBOM: false }).decode(buf) };
  } catch {
    return { status: 0, text: null };
  }
}

export async function getJson(fetchImpl: typeof fetch, url: string): Promise<JsonResult> {
  const { status, text } = await getText(fetchImpl, url);
  if (text === null) return { status, obj: null };
  try {
    return { status, obj: JSON.parse(text) };
  } catch {
    return { status, obj: null };
  }
}

export function parseNoteBody(body: string): string {
  const norm = body.replace(/\r\n/g, "\n");
  const sep = norm.indexOf("\n\n");
  return (sep >= 0 ? norm.slice(sep + 2) : norm).trim();
}

export function normalizeRoom(room: string, obj: unknown): RoomRead {
  const o = obj !== null && typeof obj === "object" ? (obj as Record<string, unknown>) : {};
  const rawMsgs = Array.isArray(o["messages"]) ? (o["messages"] as unknown[]) : [];
  const lastSeq = i(o["last_seq"]);
  const messages: RoomMessage[] = [];
  for (const m of rawMsgs.slice(0, MAX_MESSAGES)) {
    if (m === null || typeof m !== "object") continue;
    const md = m as Record<string, unknown>;
    const from = s(md["from"], MAX_ID);
    messages.push({
      seq: i(md["seq"]),
      ts: typeof md["ts"] === "string" ? (md["ts"] as string).slice(0, MAX_ID) : null,
      from,
      text: s(md["text"]),
      nonce: typeof md["nonce"] === "string" || typeof md["nonce"] === "number" ? String(md["nonce"]).slice(0, MAX_ID) : null,
      fromIsDidShaped: from.startsWith("did:key:"),
    });
  }
  return { room, messages, lastSeq };
}

export async function readRoom(
  fetchImpl: typeof fetch,
  room: string,
  opts?: { since?: string | number; wait?: string | number; base?: string },
): Promise<RoomRead> {
  if (!isValidName(room)) return { room, messages: [], lastSeq: null };
  const url = urlRoomRead(room, opts);
  const { obj } = await getJson(fetchImpl, url);
  return normalizeRoom(room, obj);
}

export function normalizeRooms(obj: unknown): ListedRoom[] {
  const o = obj !== null && typeof obj === "object" ? (obj as Record<string, unknown>) : {};
  const raw = (Array.isArray(o["rooms"]) ? (o["rooms"] as unknown[]) : []).slice(0, MAX_ROOM_SCAN);
  const out: ListedRoom[] = [];
  for (const r of raw) {
    if (out.length >= MAX_ROOMS) break;
    if (r === null || typeof r !== "object") continue;
    const rd = r as Record<string, unknown>;
    const name = rd["room"];
    if (typeof name !== "string" || !isValidName(name)) continue;
    if (nameIsBearerSecret(name)) continue;
    const kind = roomClass(name);
    if (kind === null) continue;
    out.push({
      room: name,
      kind,
      topic: typeof rd["topic"] === "string" ? (rd["topic"] as string).slice(0, MAX_TEXT) : null,
      lastSeq: i(rd["last_seq"]),
    });
  }
  return out;
}

export async function readRooms(fetchImpl: typeof fetch, base: string = TECHNOCORE_BASE): Promise<ListedRoom[]> {
  const { obj } = await getJson(fetchImpl, urlRoomsList(base));
  return normalizeRooms(obj);
}

export async function readNote(
  fetchImpl: typeof fetch,
  namespace: string,
  key: string,
  base: string = TECHNOCORE_BASE,
): Promise<string | null> {
  if (!isValidName(namespace) || !isValidName(key)) return null;
  const { text } = await getText(fetchImpl, urlNoteGet(namespace, key, base));
  if (text === null) return null;
  const value = parseNoteBody(text);
  return value.length > 0 ? value.slice(0, MAX_TEXT) : null;
}

export function normalizeBoard(obj: unknown): BoardRead {
  const o = obj !== null && typeof obj === "object" ? (obj as Record<string, unknown>) : {};
  const rawJobs = Array.isArray(o["jobs"]) ? (o["jobs"] as unknown[]) : [];
  const jobs: BoardJob[] = [];
  for (const j of rawJobs.slice(0, MAX_JOBS)) {
    if (j === null || typeof j !== "object") continue;
    const jd = j as Record<string, unknown>;
    const cat = s(jd["category"], MAX_ID);
    const status = s(jd["status"], MAX_ID);
    jobs.push({
      job_id: s(jd["job_id"], MAX_ID),
      category: CATEGORIES.has(cat) ? cat : "",
      title: s(jd["title"]),
      body: s(jd["body"]),
      status: STATUSES.has(status) ? status : "",
      poster_did: s(jd["poster_did"], MAX_ID),
      worker_did: s(jd["worker_did"], MAX_ID),
      useful_n: nn(jd["useful_n"]),
      not_n: nn(jd["not_n"]),
      seq: i(jd["seq"]),
      result: s(jd["result"]),
      // The board advertises a SHORT lowercase-hex prefix of sha256(result), not a full hash. Keep it only
      // as a prefix here; resolveResultHashes upgrades it to the full sha256 WE compute from the result (so
      // the hash is always bound to the exact result text), and clears it if the two disagree.
      result_hash: hexPrefix(jd["result_hash"]),
    });
  }
  const stats = o["stats"] !== null && typeof o["stats"] === "object" ? (o["stats"] as Record<string, unknown>) : {};
  return { jobs, stats };
}

// Turn each job's advertised prefix into the FULL sha256 of ITS OWN result, keeping the hash only when the
// board's advertised prefix matches sha256(result). Result: result_hash is either "" or a full 64-hex hash
// that provably commits to the exact `result` text the agent will see - a board cannot decouple the two,
// and a result truncated by the read clamp fails the prefix check and becomes non-attestable.
export async function resolveResultHashes(jobs: BoardJob[]): Promise<void> {
  for (const j of jobs) {
    const advertised = j.result_hash;
    if (!j.result || !advertised) {
      j.result_hash = "";
      continue;
    }
    let full: string;
    try {
      full = await sha256Hex(j.result);
    } catch {
      j.result_hash = "";
      continue;
    }
    j.result_hash = full.startsWith(advertised) ? full : "";
  }
}

export async function readBoard(fetchImpl: typeof fetch, base: string = KIBBLE_BASE): Promise<BoardRead> {
  const { obj } = await getJson(fetchImpl, `${base}/api/board`);
  const board = normalizeBoard(obj);
  await resolveResultHashes(board.jobs);
  return board;
}

// The gateway's board-match reader: the FULL, result-bound hash the board holds for a job, or null. Returns
// null for our OWN delivery (worker_did === ourDid) so a hijacked brain can never board-match a self-attest
// - this is the trust-boundary enforcement, not the agent-side ATTESTABLE_RESULTS omission.
export async function readJobResultHash(
  fetchImpl: typeof fetch,
  jobId: string,
  ourDid: string,
  base: string = KIBBLE_BASE,
): Promise<string | null> {
  try {
    const { jobs } = await readBoard(fetchImpl, base);
    const job = jobs.find((j) => j.job_id === jobId);
    if (!job || !job.result_hash) return null;
    if (ourDid && job.worker_did === ourDid) return null;
    return job.result_hash;
  } catch {
    return null;
  }
}
