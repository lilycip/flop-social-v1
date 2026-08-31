import type { Grant } from "./shared/grant";

export interface SteerPollDeps {
  readGrants: () => Promise<unknown[]>;
  applyGrant: (grant: Grant, now: number) => Promise<{ status: string }>;
  now: () => number;
}

export interface SteerPollResult {
  applied: number;
  rejected: number;
}

const MAX_CANDIDATES = 64;

function issuedBig(g: Grant): bigint {
  try {
    return BigInt(g.issued as string | number);
  } catch {
    return -1n;
  }
}

function isGrantish(x: unknown): x is Grant {
  if (x === null || typeof x !== "object") return false;
  const g = x as Record<string, unknown>;
  return (
    typeof g["grant_id"] === "string" &&
    typeof g["owner_did"] === "string" &&
    typeof g["agent_did"] === "string" &&
    typeof g["signature"] === "string" &&
    (typeof g["issued"] === "number" || typeof g["issued"] === "string")
  );
}

export async function pollSteer(deps: SteerPollDeps): Promise<SteerPollResult> {
  let candidates: unknown[];
  try {
    candidates = await deps.readGrants();
  } catch {
    return { applied: 0, rejected: 0 };
  }
  if (!Array.isArray(candidates)) return { applied: 0, rejected: 0 };

  const seen = new Set<string>();
  const grants: Grant[] = [];
  for (const c of candidates) {
    if (!isGrantish(c)) continue;
    const id = c.grant_id as unknown as string;
    if (seen.has(id)) continue;
    seen.add(id);
    grants.push(c);
  }
  grants.sort((a, b) => {
    const d = issuedBig(b) - issuedBig(a);
    return d > 0n ? 1 : d < 0n ? -1 : 0;
  });
  const bounded = grants.slice(0, MAX_CANDIDATES);

  let applied = 0;
  let rejected = 0;
  for (const g of bounded) {
    let r: { status: string };
    try {
      r = await deps.applyGrant(g, deps.now());
    } catch {
      rejected++;
      continue;
    }
    if (r.status === "OK") {
      applied++;
      break;
    }
    rejected++;
  }
  return { applied, rejected };
}
