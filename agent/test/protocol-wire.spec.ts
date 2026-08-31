import { describe, it, expect } from "vitest";
import vectors from "../vectors/wire-vectors.json";
import {
  seg,
  urlRoomRead,
  urlNoteGet,
  urlNoteSet,
  urlNoteSetSigned,
  urlSaySigned,
} from "../src/shared/protocol";

const segCases = vectors.seg as Record<string, string>;
const urls = vectors.urls as Record<string, string>;

describe("seg() matches Python quote(s, safe='')", () => {
  for (const input of Object.keys(segCases)) {
    it(`seg(${JSON.stringify(input)})`, () => {
      expect(seg(input)).toBe(segCases[input]);
    });
  }
  it("encodes the four encodeURIComponent leaves ! * ' ( ) but keeps ~ - _ .", () => {
    expect(seg("!*'()~-_.")).toBe("%21%2A%27%28%29~-_.");
  });
});

describe("url builders match Python", () => {
  it("room read (plain, since+wait, weird chars)", () => {
    expect(urlRoomRead("kibble")).toBe(urls.room_read_plain);
    expect(urlRoomRead("kibble", { since: 42, wait: 5 })).toBe(urls.room_read_since);
    expect(urlRoomRead("a/b c")).toBe(urls.room_read_weird);
  });
  it("wait is ignored without a since", () => {
    expect(urlRoomRead("kibble", { wait: 5 })).toBe(urls.room_read_plain);
  });
  it("note get / set / set-signed", () => {
    expect(urlNoteGet("did-abcd", "link")).toBe(urls.note_get);
    expect(urlNoteSet("room-x", "hb-agent", "alive @ t")).toBe(urls.note_set);
    expect(urlNoteSetSigned("did-abcd", "link", "did:key:z6MkX", "SIG_b64url", "17", "value/with slash")).toBe(
      urls.note_set_signed,
    );
  });
  it("say-signed", () => {
    expect(urlSaySigned("kibble", "did:key:z6MkX", "SIG==", "19", "CLAIM | job=abc/def")).toBe(urls.say_signed);
  });
  it("a slash in a segment can never open a new path segment", () => {
    expect(urlNoteGet("ns", "a/b")).toBe("https://technocore.chat/kv/ns/a%2Fb");
    expect(urlSaySigned("r", "d", "s", "1", "x/y/../z")).toContain("x%2Fy%2F..%2Fz");
  });
});
