import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const AGENT_DIR = join(HERE, "..");

function readJsonc(path) {
  const src = readFileSync(path, "utf8");
  let out = "";
  let inStr = false, strCh = "", inLine = false, inBlock = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i], n = src[i + 1];
    if (inLine) { if (c === "\n") { inLine = false; out += c; } continue; }
    if (inBlock) { if (c === "*" && n === "/") { inBlock = false; i++; } continue; }
    if (inStr) { out += c; if (c === "\\") { out += src[++i] ?? ""; } else if (c === strCh) inStr = false; continue; }
    if (c === '"' || c === "'") { inStr = true; strCh = c; out += c; continue; }
    if (c === "/" && n === "/") { inLine = true; i++; continue; }
    if (c === "/" && n === "*") { inBlock = true; i++; continue; }
    out += c;
  }
  return JSON.parse(out);
}

const fails = [];
const notes = [];
function ok(msg) { process.stdout.write("[OK]   " + msg + "\n"); }
function miss(msg) { fails.push(msg); process.stdout.write("[MISS] " + msg + "\n"); }
function warn(msg) { notes.push(msg); process.stdout.write("[WARN] " + msg + "\n"); }

function has(obj, path) {
  return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj) !== undefined;
}
function doBindingNames(cfg) {
  return (cfg?.durable_objects?.bindings ?? []).map((b) => b.name);
}
function doClassNames(cfg) {
  return (cfg?.durable_objects?.bindings ?? []).map((b) => b.class_name);
}
function migratedClasses(cfg) {
  return (cfg?.migrations ?? []).flatMap((m) => m.new_sqlite_classes ?? m.new_classes ?? []);
}

let gw, ag;
try { gw = readJsonc(join(AGENT_DIR, "wrangler.jsonc")); } catch (e) { miss("cannot read wrangler.jsonc: " + e.message); }
try { ag = readJsonc(join(AGENT_DIR, "wrangler.agent.jsonc")); } catch (e) { miss("cannot read wrangler.agent.jsonc: " + e.message); }

process.stdout.write("\n== GATEWAY (wrangler.jsonc) ==\n");
if (gw) {
  gw.name === "flop-gateway" ? ok("name is flop-gateway") : miss("gateway name should be flop-gateway, is " + gw.name);
  doBindingNames(gw).includes("GOVERNOR") ? ok("GOVERNOR DO binding present") : miss("GOVERNOR DO binding missing");
  doClassNames(gw).includes("Governor") ? ok("Governor class bound") : miss("Governor class not bound");
  migratedClasses(gw).includes("Governor") ? ok("Governor SQLite migration present") : miss("Governor migration missing (DO will not persist)");
  has(gw, "triggers.crons") && gw.triggers.crons.length > 0
    ? ok("cron trigger present (the revoke/kill-switch poll runs)")
    : miss("gateway cron trigger MISSING - the STOP/revoke poll would never run on its own");
  has(gw, "ai.binding") ? ok("Workers AI binding present (" + gw.ai.binding + "; free model, no credential)")
                        : miss("Workers AI binding missing - the gateway has no model brain");
  for (const v of ["OUR_DID", "OWNER_DID", "MODEL_NAME"]) {
    has(gw, "vars." + v) ? ok("var key present: " + v + (gw.vars[v] ? " (set)" : " (empty - fill at deploy)"))
                         : miss("gateway var key missing: " + v);
  }
  notes.push("gateway service name for the agent binding: " + gw.name);
}

process.stdout.write("\n== AGENT (wrangler.agent.jsonc) ==\n");
if (ag) {
  ag.name === "flop-agent" ? ok("name is flop-agent") : miss("agent name should be flop-agent, is " + ag.name);
  doBindingNames(ag).includes("MEMORY") ? ok("MEMORY DO binding present") : miss("MEMORY DO binding missing");
  doClassNames(ag).includes("AgentMemory") ? ok("AgentMemory class bound") : miss("AgentMemory class not bound");
  migratedClasses(ag).includes("AgentMemory") ? ok("AgentMemory SQLite migration present") : miss("AgentMemory migration missing");
  has(ag, "triggers.crons") && ag.triggers.crons.length > 0 ? ok("cron trigger present (the agent wakes each minute)") : miss("agent cron trigger missing - the agent would never wake");
  const svc = (ag.services ?? []).find((s) => s.binding === "GATEWAY");
  if (!svc) miss("agent GATEWAY service binding missing");
  else {
    ok("GATEWAY service binding present");
    svc.entrypoint === "Gateway" ? ok("service entrypoint is Gateway") : miss("service entrypoint should be Gateway, is " + svc.entrypoint);
    if (gw && svc.service !== gw.name) miss("agent binds service '" + svc.service + "' but the gateway is named '" + gw.name + "'");
    else if (gw) ok("agent service target matches the gateway name");
  }
  for (const v of ["NICK", "BUDGET_READS", "BUDGET_MODEL", "BUDGET_SANDBOX", "BUDGET_WRITES", "BUDGET_MEMORY"]) {
    has(ag, "vars." + v) ? ok("var key present: " + v) : miss("agent var key missing: " + v);
  }
  const forbiddenVars = ["KEY_SEED", "MODEL_CREDENTIAL", "TASK_SECRET", "OWNER_DID", "OUR_DID"];
  for (const v of forbiddenVars) {
    has(ag, "vars." + v) ? miss("SECURITY: the agent config must NOT carry " + v + " (the agent holds nothing)") : ok("agent does not carry " + v);
  }
  doClassNames(ag).includes("Governor") ? miss("SECURITY: the agent must NOT bind the Governor DO") : ok("agent does not bind the Governor");
  (ag.services ?? []).length <= 1 ? ok("agent has only the one gateway service binding") : warn("agent has more than one service binding - confirm each is intended");
}

process.stdout.write("\n== WHAT YOU SET AT DEPLOY ==\n");
process.stdout.write("Gateway SECRETS (wrangler secret put <NAME> -c wrangler.jsonc; NEVER in a file, NEVER echoed):\n");
process.stdout.write("  [SET] KEY_SEED    your agent identity's 32-byte Ed25519 seed, hex (this IS the identity; guard it)\n");
process.stdout.write("  [SET] TASK_SECRET the value the dashboard's Deploy panel shows (private task slot)\n");
process.stdout.write("  There is NO model credential: the model runs on the native Workers AI binding, which the platform\n");
process.stdout.write("  authorizes - nothing to create, store, or leak.\n");
process.stdout.write("Gateway VARS (in wrangler.jsonc, filled per user): OUR_DID (must match KEY_SEED), OWNER_DID (your\n");
process.stdout.write("  dashboard did), MODEL_NAME (a free Workers AI model id).\n");
process.stdout.write("Agent VARS (in wrangler.agent.jsonc): NICK, TECHNOCORE_BASE (optional), BUDGET_* (defaults fine)\n");
process.stdout.write("The Cloudflare ACCOUNT API TOKEN authenticates wrangler for the DEPLOY ONLY - it is NEVER a Worker secret.\n");

process.stdout.write("\n== RESULT ==\n");
if (fails.length === 0) {
  process.stdout.write("Preflight OK: both configs are wired for deploy (" + notes.length + " note(s)).\n");
  process.exit(0);
} else {
  process.stdout.write("Preflight FAILED: " + fails.length + " problem(s) above must be fixed before deploy.\n");
  process.exit(1);
}
