import { urlRoomRead, urlNoteGet, urlRoomsList, TECHNOCORE_BASE, KIBBLE_BASE } from "./shared/protocol";
import { isValidName, roomClass, nameIsBearerSecret } from "./shared/names";

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
    });
  }
  const stats = o["stats"] !== null && typeof o["stats"] === "object" ? (o["stats"] as Record<string, unknown>) : {};
  return { jobs, stats };
}

export async function readBoard(fetchImpl: typeof fetch, base: string = KIBBLE_BASE): Promise<BoardRead> {
  const { obj } = await getJson(fetchImpl, `${base}/api/board`);
  return normalizeBoard(obj);
}
