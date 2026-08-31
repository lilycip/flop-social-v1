import { describe, it, expect } from "vitest";
import gw from "../vectors/gateway-vectors.json";
import { actionString, isSha256Hex } from "../src/shared/action";
import { singleLine, messageSigInput, noteSigInput } from "../src/shared/protocol";
import {
  importSigningKey,
  signB64url,
  verifyB64url,
  pubRawFromDid,
  didNoteNs,
  noteShardKey,
} from "../src/shared/did";
import { hexToBytes } from "../src/shared/bytes";

const dec = new TextDecoder();
const seed = hexToBytes(gw.identity_seed_hex);

describe("action_string port matches Python", () => {
  it("reproduces every kibble action string", async () => {
    for (const v of gw.kibble_vectors) {
      expect(await actionString(v.verb, v.target as Record<string, unknown>, v.verdict)).toBe(
        v.action_string,
      );
    }
  });
});

describe("single_line sweep matches Python", () => {
  it("reproduces every sweep vector", () => {
    for (const s of gw.sweep_vectors) expect(singleLine(s.raw)).toBe(s.swept);
  });
  it("sweeps each kibble action string to the stored form", () => {
    for (const v of gw.kibble_vectors) expect(singleLine(v.action_string)).toBe(v.swept);
  });
});

describe("signed byte-strings match Python", () => {
  it("message_sig_input reproduces the kibble sig inputs", () => {
    for (const v of gw.kibble_vectors) {
      expect(dec.decode(messageSigInput("kibble", v.nonce, v.swept))).toBe(v.sig_input_utf8);
    }
  });
  it("note_sig_input reproduces the note sig input", () => {
    const n = gw.note_vector;
    expect(dec.decode(noteSigInput(n.namespace, n.key, n.nonce, n.value))).toBe(n.sig_input_utf8);
  });
});

describe("Ed25519 signing is byte-identical to Python (pkcs8 import)", () => {
  it("signs every kibble sig input to the same signature", async () => {
    const key = await importSigningKey(seed);
    for (const v of gw.kibble_vectors) {
      const sig = await signB64url(key, messageSigInput("kibble", v.nonce, v.swept));
      expect(sig).toBe(v.signature);
    }
  });
  it("signs the identity note to the same signature", async () => {
    const key = await importSigningKey(seed);
    const n = gw.note_vector;
    const sig = await signB64url(key, noteSigInput(n.namespace, n.key, n.nonce, n.value));
    expect(sig).toBe(n.signature);
  });
  it("signs a chat SAY to the same signature", async () => {
    const key = await importSigningKey(seed);
    const s = gw.say_vector;
    expect(singleLine(s.text)).toBe(s.swept);
    const sig = await signB64url(key, messageSigInput(s.room, s.nonce, s.swept));
    expect(sig).toBe(s.signature);
  });
  it("§9 key-format vector: seed -> pkcs8 -> signature == Python, and verifies under our DID", async () => {
    const kf = gw.keyfmt_vector;
    const key = await importSigningKey(hexToBytes(kf.seed_hex));
    const enc = new TextEncoder();
    const sig = await signB64url(key, enc.encode(kf.message_utf8));
    expect(sig).toBe(kf.signature);
    const ok = await verifyB64url(pubRawFromDid(gw.our_did), sig, enc.encode(kf.message_utf8));
    expect(ok).toBe(true);
  });
});

describe("note namespace derivation matches Python", () => {
  it("derives did-<shard> and the key fragment from our DID", async () => {
    expect(await didNoteNs(gw.our_did)).toBe(gw.note_ns);
    const [shard, key] = await noteShardKey(gw.our_did);
    expect("did-" + shard).toBe(gw.note_ns);
    expect(key).toBe(gw.note_key);
  });
  it("isSha256Hex sanity", () => {
    expect(isSha256Hex("a".repeat(64))).toBe(true);
    expect(isSha256Hex("A".repeat(64))).toBe(false);
    expect(isSha256Hex("a".repeat(63))).toBe(false);
  });
});
