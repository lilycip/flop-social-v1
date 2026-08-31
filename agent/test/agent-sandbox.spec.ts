import { describe, it, expect } from "vitest";
import { runSandboxJob, type SandboxProvider, type SandboxCreateOpts } from "../src/agent-sandbox";

function makeProvider(
  exec: (spec: { code: string; inputs?: unknown; timeoutSec: number }) => Promise<{ stdout: string }>,
): { provider: SandboxProvider; created: SandboxCreateOpts[]; destroys: number; ids: string[] } {
  const created: SandboxCreateOpts[] = [];
  const ids: string[] = [];
  let destroys = 0;
  let n = 0;
  const provider: SandboxProvider = {
    randomId: () => `id-${n++}`,
    async create(opts) {
      created.push(opts);
      return {
        exec,
        async destroy() {
          destroys++;
        },
      };
    },
  };
  return { provider, created, get destroys() { return destroys; }, ids };
}

describe("runSandboxJob - hard knobs", () => {
  it("pure-compute job runs with NO internet and keepAlive off, and destroys after", async () => {
    const h = makeProvider(async () => ({ stdout: "42" }));
    const r = await runSandboxJob({ code: "print(6*7)" }, h.provider);
    expect(r).toEqual({ status: "OK", stdout: "42" });
    expect(h.created).toHaveLength(1);
    const opts = h.created[0]!;
    expect(opts.enableInternet).toBe(false);
    expect(opts.allowedHosts).toEqual([]);
    expect(opts.keepAlive).toBe(false);
    expect(opts.sleepAfterMs).toBeGreaterThan(0);
    expect(opts.id).toBe("id-0");
    expect(h.destroys).toBe(1);
  });

  it("a fresh random id is minted per job (the id is the isolation boundary)", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    await runSandboxJob({ code: "a" }, h.provider);
    await runSandboxJob({ code: "b" }, h.provider);
    expect(h.created.map((o) => o.id)).toEqual(["id-0", "id-1"]);
  });

  it("a fetch job gets RESTRICTED internet, only the allowlisted hosts, never open", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    await runSandboxJob({ code: "fetch()", allowedHosts: ["api.example.com", "", "  " as unknown as string] }, h.provider);
    const opts = h.created[0]!;
    expect(opts.enableInternet).toBe(true);
    expect(opts.allowedHosts).toEqual(["api.example.com"]);
  });

  it("empty allowedHosts array falls back to NO internet", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    await runSandboxJob({ code: "c", allowedHosts: [] }, h.provider);
    expect(h.created[0]!.enableInternet).toBe(false);
  });

  it("drops UNSAFE egress hosts (IP literals, cloud-metadata, localhost, internal names)", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    await runSandboxJob(
      {
        code: "fetch()",
        allowedHosts: [
          "169.254.169.254", // cloud-metadata IP -> dropped
          "127.0.0.1", // loopback IP -> dropped
          "localhost", // -> dropped
          "metadata", // single-label internal -> dropped
          "db.internal", // internal TLD -> dropped
          "printer.local", // -> dropped
          "api.example.com:8080", // port / odd char -> dropped
          "api.example.com", // the one real public host -> KEPT
        ],
      },
      h.provider,
    );
    const opts = h.created[0]!;
    expect(opts.allowedHosts).toEqual(["api.example.com"]);
    expect(opts.enableInternet).toBe(true);
  });

  it("if EVERY allowlisted host is unsafe, the sandbox gets NO internet (fails safe, not open)", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    await runSandboxJob({ code: "fetch()", allowedHosts: ["169.254.169.254", "localhost", "metadata"] }, h.provider);
    expect(h.created[0]!.allowedHosts).toEqual([]);
    expect(h.created[0]!.enableInternet).toBe(false);
  });

  it("destroys the sandbox even when exec THROWS (no leak keeps billing/running)", async () => {
    const h = makeProvider(async () => {
      throw new Error("job blew up");
    });
    const r = await runSandboxJob({ code: "boom" }, h.provider);
    expect(r).toEqual({ status: "ERROR" });
    expect(h.destroys).toBe(1);
  });

  it("rejects an empty job without creating a sandbox", async () => {
    const h = makeProvider(async () => ({ stdout: "x" }));
    const r = await runSandboxJob({ code: "" }, h.provider);
    expect(r).toEqual({ status: "ERROR" });
    expect(h.created).toHaveLength(0);
    expect(h.destroys).toBe(0);
  });

  it("bounds untrusted stdout: an oversized result is ERROR (still destroys)", async () => {
    const huge = "x".repeat(1_000_001);
    const h = makeProvider(async () => ({ stdout: huge }));
    const r = await runSandboxJob({ code: "spew" }, h.provider);
    expect(r).toEqual({ status: "ERROR" });
    expect(h.destroys).toBe(1);
  });
});
