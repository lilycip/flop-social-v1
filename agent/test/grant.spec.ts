import { describe, it, expect } from "vitest";
import vectors from "../vectors/grant-vectors.json";
import { didFromPubRaw, pubRawFromDid } from "../src/shared/did";
import { bytesToHex, hexToBytes } from "../src/shared/bytes";
import { isValidName } from "../src/shared/names";
import {
  authorizedCeiling,
  autoCeiling,
  grantClass,
  grantMessage,
  isDangerous,
  verifyGrant,
  type Grant,
} from "../src/shared/grant";

const ownerPub = hexToBytes(vectors.owner_pub_raw_hex);
const dec = new TextDecoder();

describe("did port matches Python", () => {
  it("resolves seed->did->pub_raw both directions", () => {
    for (const v of vectors.did_vectors) {
      const pub = hexToBytes(v.pub_raw_hex);
      expect(didFromPubRaw(pub)).toBe(v.did);
      expect(bytesToHex(pubRawFromDid(v.did))).toBe(v.pub_raw_hex);
    }
  });
});

describe("grant_message is byte-identical to Python", () => {
  it("reproduces every message vector", () => {
    for (const v of vectors.message_vectors) {
      const bytes = grantMessage(
        v.grant_id,
        vectors.owner_did,
        vectors.agent_did,
        v.issued,
        v.expiry,
        v.window,
        v.allow as Record<string, number>,
      );
      expect(dec.decode(bytes)).toBe(v.message_utf8);
    }
  });
});

describe("verify_grant reproduces every branch", () => {
  for (const v of vectors.verify_vectors) {
    it(v.name, async () => {
      const revoked = new Set<string>(v.revoked);
      const got = await verifyGrant(ownerPub, v.grant as Grant, v.now, revoked, v.expected_agent);
      expect(got).toBe(v.want);
    });
  }

  it("rejects a missing clock / revoked set (required args)", async () => {
    const good = vectors.good_grant as Grant;
    expect(await verifyGrant(ownerPub, good, null, new Set(), vectors.agent_did)).toBe(false);
    expect(await verifyGrant(ownerPub, good, 1500, null, vectors.agent_did)).toBe(false);
    expect(await verifyGrant(null, good, 1500, new Set(), vectors.agent_did)).toBe(false);
  });
});

describe("grant_class and authorized_ceiling match Python", () => {
  it("reproduces class + ceiling for every action vector", async () => {
    const good = vectors.good_grant as Grant;
    for (const v of vectors.ceiling_vectors) {
      expect(grantClass(v.verb, v.target, v.verdict, v.board_match)).toBe(v.klass);
      const ac = await autoCeiling(
        ownerPub,
        good,
        v.verb,
        v.target,
        v.verdict,
        v.board_match,
        1500,
        new Set(),
        vectors.agent_did,
      );
      expect(ac).toBe(v.ceiling);
    }
  });

  it("authorized_ceiling collapses zero and missing to null", () => {
    const g = { allow: { CLAIM: 0, RESULT: 3 } } as unknown as Grant;
    expect(authorizedCeiling(g, "CLAIM")).toBe(null);
    expect(authorizedCeiling(g, "RESULT")).toBe(3);
    expect(authorizedCeiling(g, "NOPE")).toBe(null);
  });
});

describe("name grammar parity with Python fullmatch", () => {
 it("rejects a trailing newline, exactly like Python's fullmatch", () => {
    expect(isValidName("room")).toBe(true);
    expect(isValidName("room\n")).toBe(false);
    expect(isValidName("abc\n")).toBe(false);
    expect(isValidName("a\nb")).toBe(false);
    expect(isValidName("")).toBe(false);
  });
});

describe("is_dangerous matches Python", () => {
  it("flags exactly the audited dangerous classes", () => {
    for (const v of vectors.dangerous_vectors) {
      expect(isDangerous(v.klass)).toBe(v.dangerous);
    }
  });
});
