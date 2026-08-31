import { isIpLiteral } from "./agent-fetch";

const INTERNAL_SUFFIX = [".local", ".internal", ".localhost", ".lan", ".home", ".corp"];
function isUnsafeEgressHost(host: string): boolean {
  if (!host) return true;
  if (isIpLiteral(host)) return true;
  if (host === "localhost") return true;
  if (!host.includes(".")) return true;
  if (INTERNAL_SUFFIX.some((s) => host.endsWith(s))) return true;
  if (!/^[a-z0-9.-]+$/.test(host)) return true;
  return false;
}

export interface SandboxSpec {
  code: string;
  inputs?: unknown;
  allowedHosts?: readonly string[];
  timeoutSec?: number;
}

export interface SandboxCreateOpts {
  id: string;
  enableInternet: boolean;
  allowedHosts: readonly string[];
  sleepAfterMs: number;
  keepAlive: false;
}

export interface SandboxHandle {
  exec(spec: { code: string; inputs?: unknown; timeoutSec: number }): Promise<{ stdout: string }>;
  destroy(): Promise<void>;
}

export interface SandboxProvider {
  create(opts: SandboxCreateOpts): Promise<SandboxHandle>;
  randomId(): string;
}

export const SandboxStatus = {
  OK: "OK",
  ERROR: "ERROR", // create/exec/destroy failure - fixed status, never echoes the cause
} as const;
export type SandboxStatusValue = (typeof SandboxStatus)[keyof typeof SandboxStatus];

export type SandboxResult = { status: "OK"; stdout: string } | { status: "ERROR" };

const DEFAULT_SLEEP_AFTER_MS = 5_000;
const DEFAULT_TIMEOUT_SEC = 20;
const MAX_STDOUT = 1_000_000;

export async function runSandboxJob(spec: SandboxSpec, provider: SandboxProvider): Promise<SandboxResult> {
  if (typeof spec?.code !== "string" || spec.code.length === 0) return { status: "ERROR" };

  const allowedHosts = Array.isArray(spec.allowedHosts)
    ? spec.allowedHosts
        .map((h) => (typeof h === "string" ? h.trim().toLowerCase() : ""))
        .filter((h) => h.length > 0 && !isUnsafeEgressHost(h))
    : [];
  const enableInternet = allowedHosts.length > 0;

  const opts: SandboxCreateOpts = {
    id: provider.randomId(), // FRESH + random every job: the id is the isolation boundary
    enableInternet,
    allowedHosts,
    sleepAfterMs: DEFAULT_SLEEP_AFTER_MS,
    keepAlive: false,
  };

  let handle: SandboxHandle | null = null;
  try {
    handle = await provider.create(opts);
    const timeoutSec =
      typeof spec.timeoutSec === "number" && spec.timeoutSec > 0 && spec.timeoutSec <= 120
        ? spec.timeoutSec
        : DEFAULT_TIMEOUT_SEC;
    const out = await handle.exec({ code: spec.code, inputs: spec.inputs, timeoutSec });
    const stdout = typeof out?.stdout === "string" ? out.stdout : "";
    if (stdout.length > MAX_STDOUT) return { status: "ERROR" };
    return { status: "OK", stdout };
  } catch {
    return { status: "ERROR" };
  } finally {
    if (handle) {
      try {
        await handle.destroy();
      } catch {
        /* a destroy failure must not surface a cause; the sleepAfter is the backstop */
      }
    }
  }
}
