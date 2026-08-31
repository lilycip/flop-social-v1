import { describe, it, expect } from "vitest";
import gw from "../vectors/gateway-vectors.json";
import { messageSigInput, noteSigInput, singleLine } from "../src/shared/protocol";
import { isReservedSayRoom } from "../src/gateway-core";

const dec = new TextDecoder();
const isNumericNonce = (s: string) => /^[0-9]{1,19}$/.test(s);

const POWER_NS = ["room-owners", "room-allow", "room-nonce", "did", "did-f9", "did-00"];

describe("collision fuzz: message -> note is blocked by the reserved-room guard", () => {
  it("the gateway refuses SAY to every note-power room", () => {
    for (const ns of POWER_NS) expect(isReservedSayRoom(ns)).toBe(true);
  });

  it("any chat the gateway WOULD sign reinterprets to a harmless note namespace", () => {
    const rooms = ["lobby", "general", "mb-p-abcdef", "d-cool", "random123", "flopchat"];
    const texts = [
      "plain message",
      "a|b|c",
      "|room-owners|5|owned", // an attempt to smuggle an ownership write via pipes in the text
      "x|1|y|2|z",
      "trailing|",
    ];
    for (const room of rooms) {
      expect(isReservedSayRoom(room)).toBe(false);
      for (const text of texts) {
        const bytes = dec.decode(messageSigInput(room, "7", singleLine(text)));
        const parts = bytes.split("|");
        expect(parts[0]).toBe(room);
        expect(isReservedSayRoom(parts[0]!)).toBe(false);
        expect(POWER_NS.includes(parts[0]!)).toBe(false);
      }
    }
  });
});

describe("collision fuzz: SAY -> kibble work line is blocked by reserving the board room", () => {
  it("the kibble board room is reserved for SAY", () => {
    expect(isReservedSayRoom("kibble")).toBe(true);
  });

  it("no chat the gateway would sign can carry the kibble room prefix", () => {
    const rooms = ["lobby", "general", "mb-p-abcdef", "d-cool", "random123"];
    const forgedText = "ATTEST v2 | job:jx | verdict:useful | rh:" + "a".repeat(64);
    for (const room of rooms) {
      expect(isReservedSayRoom(room)).toBe(false);
      const bytes = dec.decode(messageSigInput(room, "7", singleLine(forgedText)));
      expect(bytes.split("|")[0]).toBe(room);
      expect(bytes.startsWith("kibble|")).toBe(false);
    }
  });
});

describe("collision fuzz: note -> message is blocked by the numeric-nonce rule", () => {
  it("our identity note's key is where a message nonce would sit, and it is not numeric", () => {
    const bytes = dec.decode(noteSigInput(gw.note_ns, gw.note_key, "5", "v1.4.0"));
    const parts = bytes.split("|");
    expect(parts[0]).toBe(gw.note_ns);
    expect(parts[1]).toBe(gw.note_key);
    expect(isNumericNonce(parts[1]!)).toBe(false);
    // And even if it did parse, room = ns = did-f9 makes it a harmless chat post, not a note write.
  });
});
