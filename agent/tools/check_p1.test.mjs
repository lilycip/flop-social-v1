import { findSinks, importsOf, findCoverageGaps, resolveImport, buildScanSet, agentEntryFromWrangler, stripJsonc } from "./check_p1.mjs";

let pass = 0;
let fail = 0;
function ok(cond, label) {
  if (cond) { pass++; } else { fail++; console.error(`  FAIL: ${label}`); }
}
const hasSink = (src) => findSinks(src).length > 0;

const HOSTILE = [
  ["indirect eval (0,eval)", "const r = (0,eval)(payload);"],
  ["constructor gadget", "const f = a.constructor.constructor('code'); f();"],
  ["Reflect.apply(Function)", "Reflect.apply(Function, null, ['return 1']);"],
  ["computed global ['ev'+'al']", "globalThis['ev'+'al'](x);"],
  ["computed global self['eval']", "self['eval'](x);"],
  ["multi-line split eval\\n(x)", "const y = eval\n(attacker);"],
  ["sink after // inside a string", 'const s = "a//b"; eval(attacker);'],
  ["new Function", "const g = new Function('return 1');"],
  ["dynamic import(var)", "await import(userControlled);"],
  ["require", "const fs = require('fs');"],
  ["WebAssembly", "await WebAssembly.instantiate(bytes);"],
  ["string setTimeout", "setTimeout('doThing()', 10);"],
  ["node:vm static import", 'import vm from "node:vm";'],
  ["sink inside template expr", "const t = `${eval(x)}`;"],
  ["bare Function value passed", "const ctor = Function;"],
  ["optional-chaining computed global", 'globalThis?.["eval"](x);'],
  ["optional-chaining self", 'self ?. ["eval"](x);'],
  ["unicode-escaped eval", "ev\\u0061l(payload);"],
  ["unicode-escaped Function", "new Functio\\u006e('x');"],
  ["unicode-escaped require", "requir\\u0065('fs');"],
  ["braced unicode escape", "\\u{65}val(x);"],
  ["sink after a quote-bearing regex", 'const re = /a"b/; eval(attacker);'],
  ["sink after a regex with slashes in a class", "const re = /[/]/; eval(attacker);"],
  ["sink after a regex with a // inside", "const re = /a\\/\\//; eval(attacker);"],
  ["division after ) then sink", "const r = f() / eval(payload);"],
  ["division after ] then sink", "const r = arr[0] / eval(payload);"],
  ["division after } then sink", "const r = obj[k]?.() / eval(payload);"],
  ["keyword-preceded regex with quote then sink", 'function f(){ return /re"/; }\neval(z);'],
  ["typeof regex with quote then sink", 'const t = typeof /a"/; eval(z);'],
  ['regex-after-) dquote then sink', 'if (x) /"/.test(y); eval(attacker);'],
  ["regex-after-) squote then sink", "if (x) /'/.test(y); eval(attacker);"],
  ["regex-after-) backtick then sink", "if (x) /`/.test(y); eval(attacker);"],
  ["regex-after-] then sink", 'const r = arr[0]; if (arr[1]) /"/.test(z); Function("bad")();'],
  ["while-guard regex then sink", 'while (go) /"/.test(s); require("fs");'],
  ["multiline guard regex then sink", 'if (allow) /"/.test(name);\n  eval(payload);\n  log("done");'],
  ["export default regex then sink", 'export default /"/;\neval(attacker);'],
  ["extends regex then sink", 'class X extends /"/ {}\neval(attacker);'],
  ["computed constructor gadget", 'export function runJob(code){ return []["constructor"]["constructor"](code)(); }'],
  ["object computed constructor", '({})["constructor"]["constructor"]("x")();'],
  ["aliased constructor key", 'const k = "constructor"; ({})[k][k]("x")();'],
  ["node builtin subpath import", 'import fs from "node:fs/promises";'],
  ["bare builtin subpath import", 'import fs from "fs/promises";'],
];
for (const [label, src] of HOSTILE) ok(hasSink(src), `hostile caught: ${label}`);

const CLEAN = [
  ["line comment mentioning sinks", "// no eval / Function / require / import() / vm here"],
  ["block comment mentioning sinks", "/* eval Function require WebAssembly */ const x = 1;"],
  ["sink words inside a string", 'const msg = "please do not eval or require this";'],
  ["class constructor method", "class B { constructor(x) { this.x = x; } }"],
  ["import.meta (no paren)", "const u = import.meta.url;"],
  ["setTimeout with function arg", "setTimeout(fn, 1000);"],
  ["ordinary call ending in Function-ish name", "const r = computeFunctionally(x);"],
  ["static named import", 'import { runPass } from "./agent-core";'],
  ["template with harmless expr", "const t = `hi ${okFn(y)} there`;"],
  ["string containing */ and //", 'const accept = "text/html, */*; q=0.1 // not a comment";'],
  ["type import from outside set", 'import type { Gateway } from "./index";'],
  ["legit quote-free regex + .exec", "const m = /^(\\d{1,3})\\.(\\d{1,3})$/.exec(host);"],
  ["division operator, not regex", "const r = totalBytes / chunkCount;"],
  ["regex then division", "const a = /x/; const b = count / 2;"],
  ["identifier division then a string with a sink word", 'const r = a / b; const s = "you can require login";'],
  ["number division then a string with a sink word", 'const r = total / 2; const s = "please eval later";'],
  ["division chain then normal string", 'const r = a / b / c; const s = "hello world";'],
  ["call division then string with sink word", 'const r = f() / n; const m = "please eval later";'],
  ["bracket division then string with sink word", 'const r = arr[0] / n; const s = "require login";'],
  ["property access then division", "const r = obj.count / 2; const s = totalFunctionCalls;"],
];
for (const [label, src] of CLEAN) ok(!hasSink(src), `clean passes: ${label}`);

{
  const a = importsOf('import { runPass, type PassDeps } from "./agent-core";');
  ok(a.length === 1 && a[0].spec === "./agent-core" && a[0].typeOnly === false, "runtime named import is not type-only");
  const b = importsOf('import type { Gateway } from "./index";');
  ok(b.length === 1 && b[0].typeOnly === true, "whole-statement type import is type-only");
  const c = importsOf('import { type A, type B } from "./x";');
  ok(c.length === 1 && c[0].typeOnly === true, "all-specifiers-type import is type-only");
  const d = importsOf('import "./sideeffect";');
  ok(d.length === 1 && d[0].spec === "./sideeffect" && d[0].typeOnly === false, "side-effect import is runtime");
}

{
  const scan = ["agent-core.ts", "agent-index.ts"];
  const imports = {
    "agent-core.ts": [],
    "agent-index.ts": [
      { spec: "./agent-core", typeOnly: false }, // in set -> ok
      { spec: "./index", typeOnly: true }, // outside set but type-only -> ok
    ],
  };
  ok(findCoverageGaps(scan, (f) => imports[f]).length === 0, "no gap when deps are in-set or type-only");

  const imports2 = { "agent-core.ts": [{ spec: "./helper", typeOnly: false }], "agent-index.ts": [] };
  const gaps2 = findCoverageGaps(scan, (f) => imports2[f]);
  ok(gaps2.length === 1 && gaps2[0].spec === "./helper", "runtime import of an unscanned file is a gap");
}

{
  ok(resolveImport("agent-index.ts", "./agent-core") === "agent-core.ts", "sibling resolves");
  ok(resolveImport("agent-index.ts", "./shared/protocol") === "shared/protocol.ts", "into a subdir resolves");
  ok(resolveImport("shared/protocol.ts", "./bytes") === "shared/bytes.ts", "sibling inside a subdir resolves");
  ok(resolveImport("shared/protocol.ts", "../agent-core") === "agent-core.ts", ".. climbs out of a subdir");
  ok(resolveImport("agent-index.ts", "./protocol-read.ts") === "protocol-read.ts", "an explicit .ts extension is normalised");
  ok(resolveImport("a/b/c.ts", "./d") === "a/b/d.ts", "nested sibling resolves");
}

{
  const graph = {
    "agent-index.ts": 'import { runPass } from "./agent-core";\nimport { readRoom } from "./protocol-read";\nimport type { Gateway } from "./index";',
    "agent-core.ts": 'import type { X } from "./gateway-core";\nexport const y = 1;',
    "protocol-read.ts": 'import { seg } from "./shared/protocol";\nimport pkg from "some-package";',
    "shared/protocol.ts": 'import { utf8 } from "./bytes";',
    "shared/bytes.ts": "export const utf8 = (s) => s;",
  };
  const readFile = (rel) => {
    if (!(rel in graph)) { const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; }
    return graph[rel];
  };
  const { files, errors } = buildScanSet(readFile, ["agent-index.ts"]);
  const set = [...files.keys()].sort().join(",");
  ok(set === "agent-core.ts,agent-index.ts,protocol-read.ts,shared/bytes.ts,shared/protocol.ts",
     "closure follows runtime relative imports through subdirs and stops at type-only/bare");
  ok(!files.has("index.ts"), "a type-only import (./index) is NOT pulled into the isolate closure");
  ok(errors.length === 0, "no read errors when every reached file exists");

  const graph2 = { "agent-index.ts": 'import { gone } from "./missing";' };
  const { files: f2, errors: e2 } = buildScanSet((rel) => {
    if (!(rel in graph2)) { const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; }
    return graph2[rel];
  }, ["agent-index.ts"]);
  ok(e2.length === 1 && e2[0].rel === "missing.ts", "an unreadable reached file is recorded as an error");
  ok(f2.get("missing.ts") === null, "the unreadable file is marked null, not silently dropped");
}

{
  const wrangler = `{
    // the agent worker
    "name": "flop-agent",
    "main": "src/agent-index.ts", // the entry
    "vars": { "NICK": "agent" }
    /* TODO(4e): the Sandbox DO
       "durable_objects": { "bindings": [ { "class_name": "Sandbox" } ] } */
  }`;
  ok(agentEntryFromWrangler(wrangler) === "agent-index.ts", "reads main from JSONC, strips src/ + comments");
  const wrangler2 = '{ /* "main": "src/DECOY.ts" */ "main": "src/agent-index.ts" }';
  ok(agentEntryFromWrangler(wrangler2) === "agent-index.ts", "a commented-out main/decoy is ignored");
  ok(stripJsonc('{"u":"https://x/y"}').includes("https://x/y"), "a // inside a string is preserved");
  let threw = false;
  try { agentEntryFromWrangler('{ "name": "x" }'); } catch { threw = true; }
  ok(threw, "a missing main throws (gate fails closed)");
  threw = false;
  try { agentEntryFromWrangler('{ "main": "elsewhere/x.ts" }'); } catch { threw = true; }
  ok(threw, "a main not under src/ throws (gate fails closed)");
}

console.log(`P1 gate unit test: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
