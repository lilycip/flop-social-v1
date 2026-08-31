import { b64urlToBytes, bytesEqual, bytesToB64url, hexToBytes, sha256Hex } from "./bytes";

const PKCS8_PREFIX_HEX = "302e020100300506032b657004220420";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX: Record<string, number> = {};
for (let i = 0; i < B58.length; i++) B58_INDEX[B58[i]!] = i;

const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);
const DID_PREFIX = "did:key:z";

function b58encode(b: Uint8Array): string {
  let n = 0n;
  for (const byte of b) n = n * 256n + BigInt(byte);
  let out = "";
  while (n > 0n) {
    const r = Number(n % 58n);
    out = B58[r]! + out;
    n = n / 58n;
  }
  let pad = 0;
  for (const byte of b) {
    if (byte === 0) pad++;
    else break;
  }
  return "1".repeat(pad) + out;
}

function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const i = B58_INDEX[ch];
    if (i === undefined) throw new Error(`not base58btc: ${ch}`);
    n = n * 58n + BigInt(i);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n = n >> 8n;
  }
  let pad = 0;
  for (const ch of s) {
    if (ch === "1") pad++;
    else break;
  }
  const out = new Uint8Array(pad + body.length);
  out.set(body, pad);
  return out;
}

export function didFromPubRaw(pub: Uint8Array): string {
  if (pub.length !== 32) throw new Error(`ed25519 public key must be 32 bytes, got ${pub.length}`);
  const payload = new Uint8Array(ED25519_MULTICODEC.length + pub.length);
  payload.set(ED25519_MULTICODEC, 0);
  payload.set(pub, ED25519_MULTICODEC.length);
  return DID_PREFIX + b58encode(payload);
}

export function pubRawFromDid(did: string): Uint8Array {
  if (typeof did !== "string" || !did.startsWith(DID_PREFIX)) {
    throw new Error("not a did:key:z... string");
  }
  const raw = b58decode(did.slice(DID_PREFIX.length));
  if (raw.length < 2 || raw[0] !== ED25519_MULTICODEC[0] || raw[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("did:key is not ed25519-pub multicodec");
  }
  const pub = raw.slice(2);
  if (pub.length !== 32) throw new Error("decoded ed25519 key is not 32 bytes");
  return pub;
}

export function pubRawEquals(did: string, pub: Uint8Array): boolean {
  try {
    return bytesEqual(pubRawFromDid(did), pub);
  } catch {
    return false;
  }
}

export async function verifyB64url(
  pub: Uint8Array,
  sigB64url: string,
  message: Uint8Array,
): Promise<boolean> {
  try {
    const sig = b64urlToBytes(sigB64url);
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, message);
  } catch {
    return false;
  }
}

export async function importSigningKey(seed: Uint8Array): Promise<CryptoKey> {
  if (seed.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  const prefix = hexToBytes(PKCS8_PREFIX_HEX);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(seed, prefix.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

export async function signB64url(key: CryptoKey, message: Uint8Array): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, message));
  return bytesToB64url(sig);
}

export async function fingerprint(did: string): Promise<string> {
  return (await sha256Hex(did)).slice(0, 16);
}

export async function noteShardKey(did: string): Promise<[string, string]> {
  const fp = await fingerprint(did);
  return [fp.slice(0, 2), fp.slice(2)];
}

export async function didNoteNs(did: string): Promise<string> {
  const [shard] = await noteShardKey(did);
  return "did-" + shard;
}
