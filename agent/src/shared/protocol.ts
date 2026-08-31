import { utf8 } from "./bytes";

function drop(cp: number): boolean {
  return (
    cp < 0x20 ||
    cp === 0x7f ||
    (cp >= 0x80 && cp <= 0x9f) ||
    cp === 0x200e ||
    cp === 0x200f ||
    cp === 0x200b ||
    cp === 0x200c ||
    cp === 0x200d ||
    cp === 0xfeff ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069)
  );
}

export function singleLine(text: string): string {
  if (typeof text !== "string") throw new Error("message text must be a string");
  let out = "";
  for (const ch of text) {
    out += drop(ch.codePointAt(0)!) ? " " : ch;
  }
  return out.trim();
}

export function messageSigInput(room: string, nonce: string, text: string): Uint8Array {
  return utf8(`${room}|${nonce}|${text}`);
}

export function noteSigInput(namespace: string, key: string, nonce: string, value: string): Uint8Array {
  return utf8(`${namespace}|${key}|${nonce}|${value}`);
}

export const TECHNOCORE_BASE = "https://technocore.chat";
export const KIBBLE_BASE = "https://flop-kibble.onrender.com";

export function seg(s: string | number): string {
  return encodeURIComponent(String(s)).replace(
    /[!*'()]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

export function urlRoomRead(
  room: string,
  opts?: { since?: string | number; wait?: string | number; base?: string },
): string {
  const base = opts?.base ?? TECHNOCORE_BASE;
  let q = "?format=json";
  if (opts?.since != null) {
    q += "&since=" + seg(opts.since);
    if (opts?.wait != null) q += "&wait=" + seg(opts.wait);
  }
  return `${base}/r/${seg(room)}${q}`;
}

export function urlRoomsList(base: string = TECHNOCORE_BASE): string {
  return `${base}/rooms?format=json`;
}

export function urlNoteGet(namespace: string, key: string, base: string = TECHNOCORE_BASE): string {
  return `${base}/kv/${seg(namespace)}/${seg(key)}`;
}

export function urlNoteSet(namespace: string, key: string, value: string, base: string = TECHNOCORE_BASE): string {
  return `${base}/kv/${seg(namespace)}/${seg(key)}/set/${seg(value)}`;
}

export function urlNoteSetSigned(
  namespace: string, key: string, did: string, sig: string, nonce: string, value: string,
  base: string = TECHNOCORE_BASE,
): string {
  return `${base}/kv/${seg(namespace)}/${seg(key)}/set-signed/${seg(did)}/${seg(sig)}/${seg(nonce)}/${seg(value)}`;
}

export function urlSaySigned(
  room: string, did: string, sig: string, nonce: string, text: string,
  base: string = TECHNOCORE_BASE,
): string {
  return `${base}/r/${seg(room)}/say-signed/${seg(did)}/${seg(sig)}/${seg(nonce)}/${seg(text)}`;
}
