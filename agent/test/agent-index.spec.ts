import { describe, it, expect } from "vitest";
import { makeProtocolIO } from "../src/agent-index";

function scriptedFetch(routes: Array<[string, unknown, number?]>): { fetch: typeof fetch; seen: string[] } {
  const seen: string[] = [];
  const impl = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    seen.push(url);
    for (const [needle, body, status] of routes) {
      if (url.includes(needle)) {
        return new Response(typeof body === "string" ? body : JSON.stringify(body), { status: status ?? 200 });
      }
    }
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  return { fetch: impl, seen };
}

describe("makeProtocolIO.readBoard", () => {
  it("reads the kibble board and hands each job to the brain as untrusted raw JSON", async () => {
    const { fetch, seen } = scriptedFetch([
      ["/api/board", { jobs: [{ job_id: "j1", category: "research", status: "open", title: "t", body: "b" }] }],
    ]);
    const io = makeProtocolIO(fetch, "flopbot");
    const items = await io.readBoard();
    expect(seen[0]).toBe("https://flop-kibble.onrender.com/api/board");
    expect(items).toHaveLength(1);
    const parsed = JSON.parse(items[0]!.raw);
    expect(parsed.job_id).toBe("j1");
    expect(parsed.category).toBe("research");
  });

  it("a hostile category is blanked by the 4a layer before the brain ever sees it", async () => {
    const { fetch } = scriptedFetch([["/api/board", { jobs: [{ job_id: "j", category: "__proto__", status: "open" }] }]]);
    const items = await makeProtocolIO(fetch, "n").readBoard();
    expect(JSON.parse(items[0]!.raw).category).toBe("");
  });

  it("an unreachable board degrades to an empty read, never a throw", async () => {
    const throwing = (async () => { throw new Error("net down"); }) as unknown as typeof fetch;
    await expect(makeProtocolIO(throwing, "n").readBoard()).resolves.toEqual([]);
  });
});

describe("makeProtocolIO.readMailbox", () => {
  it("reads mb-<nick> (derived from the PUBLIC nick, so the agent holds no private room name)", async () => {
    const { fetch, seen } = scriptedFetch([
      ["/r/mb-flopbot", { messages: [{ from: "did:key:z6MkX", text: "hi", seq: 1 }], last_seq: 1 }],
    ]);
    const items = await makeProtocolIO(fetch, "flopbot").readMailbox();
    expect(seen[0]).toBe("https://technocore.chat/r/mb-flopbot?format=json");
    expect(JSON.parse(items[0]!.raw).text).toBe("hi");
    expect(JSON.parse(items[0]!.raw).fromIsDidShaped).toBe(true);
  });

  it("an invalid nick cannot escape the room grammar: the 4a guard yields empty, no wire hit", async () => {
    const { fetch, seen } = scriptedFetch([["/r/", { messages: [{ text: "x" }] }]]);
    const items = await makeProtocolIO(fetch, "bad nick").readMailbox();
    expect(items).toEqual([]);
    expect(seen).toEqual([]);
  });
});

describe("makeProtocolIO.readRooms (SIGHT: the rooms the brain may post to)", () => {
  it("reads /rooms?format=json and returns classified public rooms", async () => {
    const { fetch, seen } = scriptedFetch([
      ["/rooms?format=json", { rooms: [{ room: "lobby", topic: "hub", last_seq: 9 }, { room: "d-jobs" }] }],
    ]);
    const rooms = await makeProtocolIO(fetch, "n").readRooms();
    expect(seen[0]).toBe("https://technocore.chat/rooms?format=json");
    expect(rooms.map((r) => r.room)).toEqual(["lobby", "d-jobs"]);
    expect(rooms[0]).toMatchObject({ kind: "open", topic: "hub" });
  });

  it("a bearer-secret room in a hostile body never reaches the brain", async () => {
    const { fetch } = scriptedFetch([["/rooms", { rooms: [{ room: "lobby" }, { room: "p-secretname99" }] }]]);
    const rooms = await makeProtocolIO(fetch, "n").readRooms();
    expect(rooms.map((r) => r.room)).toEqual(["lobby"]);
  });

  it("an unreachable rooms endpoint degrades to an empty read, never a throw", async () => {
    const throwing = (async () => { throw new Error("net down"); }) as unknown as typeof fetch;
    await expect(makeProtocolIO(throwing, "n").readRooms()).resolves.toEqual([]);
  });
});

describe("makeProtocolIO.lookRoom (a bounded peek into one room)", () => {
  it("reads the named room and returns only the recent from/text/seq tail", async () => {
    const { fetch, seen } = scriptedFetch([
      ["/r/lobby", { messages: [{ from: "did:key:zA", text: "hi", seq: 1, nonce: "5" }], last_seq: 1 }],
    ]);
    const view = await makeProtocolIO(fetch, "n").lookRoom("lobby");
    expect(seen[0]).toBe("https://technocore.chat/r/lobby?format=json");
    expect(view).toEqual({ room: "lobby", messages: [{ from: "did:key:zA", text: "hi", seq: 1 }], lastSeq: 1 });
  });

  it("an invalid room name never hits the wire and returns an empty view", async () => {
    const { fetch, seen } = scriptedFetch([]);
    const view = await makeProtocolIO(fetch, "n").lookRoom("BAD NAME");
    expect(view.messages).toEqual([]);
    expect(seen).toEqual([]);
  });

 it("FAILS CLOSED on a bearer-secret room: never fetches it, returns empty", async () => {
    const { fetch, seen } = scriptedFetch([["/r/", { messages: [{ from: "x", text: "secret", seq: 1 }], last_seq: 1 }]]);
    for (const secret of ["p-deadbeefcafe", "mb-p-privatebox"]) {
      const view = await makeProtocolIO(fetch, "n").lookRoom(secret);
      expect(view.messages).toEqual([]);
    }
    expect(seen).toEqual([]);
  });
});

describe("makeProtocolIO.postPresence", () => {
  it("writes an UNSIGNED hb-<nick> note to the kibble namespace with an epoch-seconds value", async () => {
    const { fetch, seen } = scriptedFetch([]);
    await makeProtocolIO(fetch, "flopbot").postPresence("flopbot");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^https:\/\/technocore\.chat\/kv\/kibble\/hb-flopbot\/set\/\d+$/);
    expect(seen[0]).not.toContain("set-signed");
  });

  it("a presence write failure never throws out of the seam", async () => {
    const throwing = (async () => { throw new Error("down"); }) as unknown as typeof fetch;
    await expect(makeProtocolIO(throwing, "n").postPresence("n")).rejects.toThrow();
    // (runPass wraps postPresence in try/catch; here we only assert the seam itself surfaces the error
    // to that wrapper rather than swallowing it silently, which would hide a broken presence forever.)
  });
});

describe("makeProtocolIO.sendSigned (the previously-missing wire-send + read-back)", () => {
  const sayResult = {
    status: "OK" as const, shape: "say" as const, did: "did:key:z6MkX",
    signature: "SIG", nonce: "1700", room: "lobby", text: "hello world",
  };

  const noSleep = { sleep: async () => {} };

  it("posts a say via the say-signed GET path (NOT a POST) and CONFIRMS it by reading it back", async () => {
    const { fetch, seen } = scriptedFetch([
      ["/say-signed", "posted", 200],
      ["?format=json", { messages: [{ from: "did:key:z6MkX", nonce: "1700", text: "hello world", seq: 5 }], last_seq: 5 }],
    ]);
    const out = await makeProtocolIO(fetch, "n", noSleep).sendSigned(sayResult);
    expect(out.sent).toBe(true);
    expect(out.confirmed).toBe(true);
    const writeUrl = seen.find((u) => u.includes("say-signed"))!;
    expect(writeUrl).toBe("https://technocore.chat/r/lobby/say-signed/did%3Akey%3Az6MkX/SIG/1700/hello%20world");
  });

  it("reports confirmed:false when the read-back never shows our message (a 200 is not persistence)", async () => {
    const { fetch } = scriptedFetch([
      ["/say-signed", "posted", 200],
      ["?format=json", { messages: [{ from: "did:key:zOTHER", nonce: "9", text: "not ours", seq: 1 }], last_seq: 1 }],
    ]);
    const out = await makeProtocolIO(fetch, "n", noSleep).sendSigned(sayResult);
    expect(out.sent).toBe(true);
    expect(out.confirmed).toBe(false);
  });

  it("CONFIRMS on a later read-back when the write landed but lagged (retry recovers a false-negative)", async () => {
    let reads = 0;
    const laggy = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/say-signed")) return new Response("posted", { status: 200 });
      reads += 1;
      const messages = reads >= 2 ? [{ from: "did:key:z6MkX", nonce: "1700", text: "hello world", seq: 5 }] : [];
      return new Response(JSON.stringify({ messages, last_seq: 5 }), { status: 200 });
    }) as unknown as typeof fetch;
    const out = await makeProtocolIO(laggy, "n", noSleep).sendSigned(sayResult);
    expect(out.sent).toBe(true);
    expect(out.confirmed).toBe(true);
    expect(reads).toBeGreaterThanOrEqual(2);
  });

  it("a non-2xx write is sent:false (the action did not post)", async () => {
    const { fetch } = scriptedFetch([["/say-signed", "refused", 500]]);
    const out = await makeProtocolIO(fetch, "n", noSleep).sendSigned(sayResult);
    expect(out.sent).toBe(false);
  });

  it("posts a note via the set-signed GET path and confirms via the note read-back", async () => {
    const noteResult = {
      status: "OK" as const, shape: "note" as const, did: "did:key:z6MkX",
      signature: "SIG", nonce: "3", namespace: "did-ab", key: "cdef", value: "did:key:z6MkX x25519:AAA ctr:2",
    };
    const { fetch, seen } = scriptedFetch([
      ["/set-signed", "ok", 200],
      ["/kv/did-ab/cdef", "!! UNTRUSTED CONTENT\n\ndid:key:z6MkX x25519:AAA ctr:2", 200],
    ]);
    const out = await makeProtocolIO(fetch, "n", noSleep).sendSigned(noteResult);
    expect(out.sent).toBe(true);
    expect(out.confirmed).toBe(true);
    expect(seen.find((u) => u.includes("set-signed"))).toContain("/kv/did-ab/cdef/set-signed/");
  });

  it("never throws: a wire failure is an honest sent:false", async () => {
    const throwing = (async () => { throw new Error("net down"); }) as unknown as typeof fetch;
    const out = await makeProtocolIO(throwing, "n", noSleep).sendSigned(sayResult);
    expect(out).toEqual({ sent: false, confirmed: false });
  });
});
