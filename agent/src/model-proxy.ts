import type { AuthorizeResult } from "./governor";

export const ModelStatus = {
  OK: "OK",
  MODEL_GATED: "MODEL_GATED", // budget exhausted / MODEL not granted / no active grant
  MODEL_ERROR: "MODEL_ERROR", // any model failure - fixed, never echoes body/stack
  MODEL_BAD_REQUEST: "MODEL_BAD_REQUEST", // empty / oversized prompt
} as const;
export type ModelStatusValue = (typeof ModelStatus)[keyof typeof ModelStatus];

export interface ModelDeps {
  governor: { reserveModel(now: number): Promise<AuthorizeResult> };
  invoke: (prompt: string) => Promise<unknown>;
  now: () => number;
  maxPromptChars?: number;
}

export type ModelResult = { status: "OK"; text: string } | { status: Exclude<ModelStatusValue, "OK"> };

const MAX_PROMPT = 100_000;
const MAX_COMPLETION = 1_000_000;

export async function modelComplete(prompt: string, deps: ModelDeps): Promise<ModelResult> {
  if (typeof prompt !== "string" || prompt.length === 0) return { status: ModelStatus.MODEL_BAD_REQUEST };
  if (prompt.length > (deps.maxPromptChars ?? MAX_PROMPT)) return { status: ModelStatus.MODEL_BAD_REQUEST };

  let reserved: AuthorizeResult;
  try {
    reserved = await deps.governor.reserveModel(deps.now());
  } catch {
    return { status: ModelStatus.MODEL_ERROR };
  }
  if (reserved.status !== "OK") return { status: ModelStatus.MODEL_GATED };

  try {
    const data = await deps.invoke(prompt);
    const text = extractCompletion(data);
    if (typeof text !== "string" || text.length === 0) return { status: ModelStatus.MODEL_ERROR };
    if (text.length > MAX_COMPLETION) return { status: ModelStatus.MODEL_ERROR };
    return { status: "OK", text };
  } catch {
    // Fixed status only: an error body or stack could carry the model binding's internals, so it is
    // never echoed back to the untrusted agent.
    return { status: ModelStatus.MODEL_ERROR };
  }
}

function extractCompletion(data: unknown): string | null {
  if (data === null || typeof data !== "object") return null;
  const d = data as Record<string, unknown>;
  if (typeof d["response"] === "string") return d["response"] as string;
  const choices = d["choices"];
  if (Array.isArray(choices) && choices.length > 0) {
    const first = choices[0] as Record<string, unknown> | null;
    const msg = first ? (first["message"] as Record<string, unknown> | null) : null;
    const content = msg ? msg["content"] : undefined;
    if (typeof content === "string") return content;
  }
  const content = d["content"];
  if (Array.isArray(content) && content.length > 0) {
    const first = content[0] as Record<string, unknown> | null;
    const t = first ? first["text"] : undefined;
    if (typeof t === "string") return t;
  }
  return null;
}
