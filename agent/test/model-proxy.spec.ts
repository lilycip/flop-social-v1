import { describe, it, expect, vi } from "vitest";
import { modelComplete, type ModelDeps } from "../src/model-proxy";
import type { AuthorizeResult } from "../src/governor";

function deps(over: Partial<ModelDeps> = {}): ModelDeps {
  return {
    governor: { reserveModel: async (): Promise<AuthorizeResult> => ({ status: "OK" }) },
    invoke: async () => ({ response: "" }),
    now: () => 1500,
    ...over,
  };
}

describe("model proxy: reserve-before-call metering", () => {
  it("gates (and never calls the model) when the budget is exhausted", async () => {
    const invokeSpy = vi.fn(async () => ({ response: "should not run" }));
    const r = await modelComplete("hi", deps({
      governor: { reserveModel: async () => ({ status: "GATE_CEILING" }) },
      invoke: invokeSpy,
    }));
    expect(r.status).toBe("MODEL_GATED");
    expect(invokeSpy).not.toHaveBeenCalled();
  });

  it("returns the completion text on success (Workers AI native shape {response})", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ response: "the answer" }) }));
    expect(r).toEqual({ status: "OK", text: "the answer" });
  });

  it("returns the completion text on success (OpenAI-shaped body)", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ choices: [{ message: { content: "the answer" } }] }) }));
    expect(r).toEqual({ status: "OK", text: "the answer" });
  });

  it("returns the completion text on success (Anthropic-shaped body)", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ content: [{ text: "claude says hi" }] }) }));
    expect(r).toEqual({ status: "OK", text: "claude says hi" });
  });

  it("passes the exact prompt to the binding", async () => {
    let seen: string | null = null;
    await modelComplete("the exact prompt", deps({
      invoke: async (p: string) => { seen = p; return { response: "ok" }; },
    }));
    expect(seen).toBe("the exact prompt");
  });
});

describe("model proxy: never-echo / bounded on every failure path", () => {
 it("an unbounded completion -> MODEL_ERROR", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ response: "x".repeat(1_000_001) }) }));
    expect(r.status).toBe("MODEL_ERROR");
  });

  it("a non-string content field -> MODEL_ERROR", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ choices: [{ message: { content: { nested: "x" } } }] }) }));
    expect(r.status).toBe("MODEL_ERROR");
  });

  it("a thrown binding whose error carries internal detail -> MODEL_ERROR, no detail in the result", async () => {
    const SECRETISH = "internal-stack-detail-xyz";
    const r = await modelComplete("hi", deps({
      invoke: async () => { throw new Error("binding failed: " + SECRETISH); },
    }));
    expect(r.status).toBe("MODEL_ERROR");
    expect(JSON.stringify(r).includes(SECRETISH)).toBe(false);
  });

  it("an empty completion -> MODEL_ERROR", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ response: "" }) }));
    expect(r.status).toBe("MODEL_ERROR");
  });

  it("a body with no extractable completion -> MODEL_ERROR", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => ({ choices: [] }) }));
    expect(r.status).toBe("MODEL_ERROR");
  });

  it("a non-object body -> MODEL_ERROR", async () => {
    const r = await modelComplete("hi", deps({ invoke: async () => "just a string" }));
    expect(r.status).toBe("MODEL_ERROR");
  });
});

describe("model proxy: request shape", () => {
  it("rejects an empty or oversized prompt (and never meters it)", async () => {
    const invokeSpy = vi.fn(async () => ({ response: "x" }));
    expect((await modelComplete("", deps({ invoke: invokeSpy }))).status).toBe("MODEL_BAD_REQUEST");
    expect((await modelComplete("x".repeat(200_000), deps({ invoke: invokeSpy }))).status).toBe("MODEL_BAD_REQUEST");
    expect(invokeSpy).not.toHaveBeenCalled();
  });
});
