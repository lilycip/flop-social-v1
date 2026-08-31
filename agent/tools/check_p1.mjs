import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import ts from "typescript";

const here = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = join(here, "..", "src");

const REQUIRED_FILES = ["agent-core.ts", "agent-fetch.ts", "agent-sandbox.ts", "agent-index.ts"];

const BANNED_IDENTIFIERS = new Set(["eval", "Function", "require", "WebAssembly"]);
const GLOBALS = new Set(["globalThis", "self", "window", "global"]);
const NODE_BUILTINS = new Set([
  "vm", "child_process", "worker_threads", "fs", "net", "http", "https", "dgram", "cluster",
  "inspector", "module", "repl", "v8", "os", "process", "tls", "dns", "sys",
]);

function builtinRoot(spec) {
  const bare = spec.startsWith("node:") ? spec.slice(5) : spec;
  return bare.split("/")[0];
}

function isStringLiteralEq(node, val) {
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && node.text === val;
}

function parse(src, fileName = "agent.ts") {
  return ts.createSourceFile(fileName, src, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);
}

export function findSinks(src) {
  const sf = parse(src);
  const found = [];
  const at = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const flag = (node, name) => found.push({ name, line: at(node) });

  const visit = (node) => {
    if (ts.isIdentifier(node) && BANNED_IDENTIFIERS.has(node.text)) flag(node, node.text);

    if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && GLOBALS.has(node.expression.text)) {
      flag(node, "computed global access");
    }

    if (ts.isPropertyAccessExpression(node) && node.name.text === "constructor") {
      flag(node, ".constructor gadget");
    }
    if (ts.isElementAccessExpression(node) && isStringLiteralEq(node.argumentExpression, "constructor")) {
      flag(node, ".constructor gadget (computed)");
    }
    if (isStringLiteralEq(node, "constructor")) {
      flag(node, "\"constructor\" key literal");
    }

    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "Reflect" &&
      (node.name.text === "apply" || node.name.text === "construct")
    ) {
      flag(node, "Reflect.apply/construct");
    }

    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      flag(node, "dynamic import()");
    }

    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      (node.expression.text === "setTimeout" || node.expression.text === "setInterval")
    ) {
      const a0 = node.arguments[0];
      if (a0 && (ts.isStringLiteralLike(a0) || ts.isTemplateExpression(a0))) {
        flag(node, "string setTimeout/setInterval");
      }
    }

    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      NODE_BUILTINS.has(builtinRoot(node.moduleSpecifier.text))
    ) {
      flag(node, "node builtin import");
    }

    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

export function findCoverageGaps(scanFiles, importsOfFile) {
  const gaps = [];
  const inSet = new Set(scanFiles);
  for (const file of scanFiles) {
    for (const imp of importsOfFile(file)) {
      if (!imp.spec.startsWith(".")) continue;
      const target = imp.spec.replace(/^\.\//, "").replace(/\.(ts|js|mjs)$/, "") + ".ts";
      if (inSet.has(target)) continue;
      if (imp.typeOnly) continue;
      gaps.push({ file, spec: imp.spec, reason: "runtime import of an unscanned file" });
    }
  }
  return gaps;
}

export function importsOf(src) {
  const sf = parse(src);
  const out = [];
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
      out.push({ spec: st.moduleSpecifier.text, typeOnly: importIsTypeOnly(st) });
    } else if (ts.isExportDeclaration(st) && st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier)) {
      out.push({ spec: st.moduleSpecifier.text, typeOnly: !!st.isTypeOnly });
    }
  }
  return out;
}

function importIsTypeOnly(st) {
  const clause = st.importClause;
  if (!clause) return false;
  if (clause.isTypeOnly) return true;
  if (clause.name) return false;
  const nb = clause.namedBindings;
  if (!nb) return false;
  if (ts.isNamespaceImport(nb)) return false;
  if (ts.isNamedImports(nb)) {
    return nb.elements.length > 0 && nb.elements.every((el) => el.isTypeOnly);
  }
  return false;
}

export function resolveImport(fromRel, spec) {
  const parts = fromRel.split("/");
  parts.pop();
  for (const seg of spec.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return parts.join("/").replace(/\.(ts|js|mjs)$/, "") + ".ts";
}

export function stripJsonc(text) {
  let out = "";
  let inStr = false;
  let strCh = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\") { out += n ?? ""; i++; continue; }
      if (c === strCh) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") { inStr = true; strCh = c; out += c; continue; }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; continue; }
    out += c;
  }
  return out;
}

export function agentEntryFromWrangler(wranglerText) {
  const cfg = JSON.parse(stripJsonc(wranglerText).replace(/,(\s*[}\]])/g, "$1"));
  const main = cfg && cfg.main;
  if (typeof main !== "string" || main.length === 0) throw new Error('wrangler.agent.jsonc has no string "main"');
  const norm = main.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!norm.startsWith("src/")) throw new Error(`wrangler "main" (${main}) is not under src/`);
  return norm.slice("src/".length);
}

export function buildScanSet(readFile, roots) {
  const files = new Map();
  const errors = [];
  const queue = [...roots];
  while (queue.length) {
    const rel = queue.shift();
    if (files.has(rel)) continue;
    let src;
    try {
      src = readFile(rel);
    } catch (e) {
      errors.push({ rel, code: (e && (e.code || e.message)) || "unreadable" });
      files.set(rel, null);
      continue;
    }
    files.set(rel, src);
    for (const imp of importsOf(src)) {
      if (imp.typeOnly) continue;
      if (!imp.spec.startsWith(".")) continue;
      queue.push(resolveImport(rel, imp.spec));
    }
  }
  return { files, errors };
}

const WRANGLER_PATH = join(here, "..", "wrangler.agent.jsonc");

export function runGate() {
  const readFile = (rel) => readFileSync(join(SRC_DIR, ...rel.split("/")), "utf8");
  let failures = 0;

  let entry;
  try {
    entry = agentEntryFromWrangler(readFileSync(WRANGLER_PATH, "utf8"));
  } catch (e) {
    console.error(`P1 FAIL: cannot determine the agent entrypoint from wrangler.agent.jsonc (${e.message}); the gate must scan exactly what deploys`);
    return 1;
  }

  const { files, errors } = buildScanSet(readFile, [entry]);
  for (const e of errors) {
    console.error(`P1 FAIL: cannot read agent-isolate file "${e.rel}" reached from the import graph (${e.code})`);
    failures++;
  }

  for (const req of REQUIRED_FILES) {
    if (!files.has(req) || files.get(req) == null) {
      console.error(`P1 FAIL: required agent file ${req} is missing from the runtime scan closure`);
      failures++;
    }
  }

  const scanned = [];
  for (const [rel, src] of files) {
    if (src == null) continue;
    scanned.push(rel);
    for (const hit of findSinks(src)) {
      console.error(`P1 FAIL: ${rel}:${hit.line} code-exec sink [${hit.name}]`);
      failures++;
    }
  }

  if (failures > 0) {
    console.error(`\nP1 FAIL: ${failures} finding(s). The agent isolate must hold no code-exec sink and no unscanned runtime dep.`);
    return 1;
  }
  scanned.sort();
  console.log(`P1 OK: no code-exec sinks, coverage proven over ${scanned.length} agent-isolate file(s) [${scanned.join(", ")}].`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  process.exit(runGate());
}
