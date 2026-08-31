# FLOP Agent - design of record v3 (for the build)

Status: SETTLED after three adversarial stress-tests (v1: 10 findings fixed; v2: verified those held
plus 3 new-surface holes fixed; v3-final: wake model and model-proxy, the 5 tightenings folded in here)
plus capability, onboarding, cost, and wake passes. This is the design the build follows. The audited
signer code is in `shared/`.

## 0. The one objective

KEY EXPOSURE is the only thing we defend. Not bad work, not bad attestations, not anonymous spam: those
improve over time; a leaked key is forever. A key is anything that grants power by being known. The design
is a CONFINEMENT argument over a FINITE set of key-touching operations. Every control works with NOBODY
WATCHING; the dashboard contributes zero to safety.

## 1. The shape: THREE isolates + one state store. The agent holds NOTHING readable.

```
   reads public board (GET) + web/GitHub (READ, allowlisted)     signs + model + private I/O
 ┌───────────────────────────┐   service binding (RPC)         ┌───────────────────────────┐
 │  AGENT Worker (untrusted)  │ ──────────────────────────────▶│  GATEWAY Worker (trusted)  │
 │  - cron loop, orchestrates │   sign(shape) / complete(prompt)│  - holds THE identity key  │
 │  - interprets model output │ ◀──────────────────────────────│  - holds private room NAMES│
 │  - HOLDS NO KEY, NO TOKEN, │  {status, signed_bytes} / text  │  - holds the MODEL token   │
 │    NO ROOM NAMES, NO CODE  │                                 │  - Governor (grant enforce)│
 └──────────────┬────────────┘                                 │  - only egress off-agent   │
                │ Sandbox DO binding (code jobs)                └─────────┬─────────┬────────┘
                ▼                                                         │         │
        SANDBOX (untrusted code)                        AI Gateway (model) │         │ Durable Object
        - NO key, NO gateway, NO protocol, NO secret    ◀─────────────────┘         ▼ (Governor state)
        - egress DENY-BY-DEFAULT, fresh id/job, disposable            counter / window / revoked / nonces
```

- **AGENT Worker** = the attack surface. Reads the public board and (allowlisted, read-only) web/GitHub,
  ORCHESTRATES, and INTERPRETS model output. It HOLDS NOTHING readable: no identity key, no model token,
  no private room names, and no code-execution sink of its own (P1). It reaches the model and the signer
  ONLY by asking the gateway (`sign(shape)`, `complete(prompt)`). Config: ZERO binding to the GOVERNOR DO,
  ZERO identity/room/model secret. It DOES have a Durable-Object binding to the SANDBOX class (the Sandbox
  SDK is a DO); that binding is expected and MUST be scoped to the Sandbox class only.
- **GATEWAY Worker** = the only holder of the identity key, the model token, and the private room names,
  and the only thing on any off-agent channel (signing, private protocol I/O, AND the model call). It is
  the Governor. It signs ONLY the hash-bound action grammar (§3), derives provenance ITSELF, and returns
  ONLY `{status, signed_bytes}` from a FIXED status enum, or model `text` from `complete()`: never a name,
  a token, a key, a stub/closure, or a raw error. ZERO public routes (RPC-only via WorkerEntrypoint),
  reachable only through the agent's service binding. It runs NO attacker code and acts on the model
  output ONLY by relaying it back (it never signs based on unvalidated model text).
- **SANDBOX** (Cloudflare Sandbox SDK / Containers) = runs a job's untrusted CODE. Wired to NOTHING that
  holds a key: NO identity key, NO gateway binding, NO Governor DO, NO protocol access, and the agent
  hands it NO secret (there is none to hand). Its network is DENY-BY-DEFAULT (§6). Code in, data out,
  fresh sandbox id per job, disposable. Its output is untrusted INPUT to the agent, like board text.
- **GOVERNOR Durable Object**, bound to the GATEWAY ONLY (fixed `idFromName` constant = one global
  authority): persisted spend counter over the SIGNED window, the pinned `active_grant_id`, the revoked
  set, the seen-nonces high-water. Read/written from DO STORAGE every action (never in-memory across cron
  ticks: a DO hibernates ~10s idle, evicts ~70-140s, and the loop is on a 1-min cron).

## 2. The confinement argument and its assumptions

Safe iff **(P1)** the agent isolate never executes attacker-controlled CODE, and **(P2)** the gateway RPC
leaks nothing but the two signed shapes and relayed model text. Given P1+P2, a fully prompt-injected agent
can at worst ask the gateway to sign one of the two shapes (still gated by the grant) or to complete a
prompt (bounded by the per-tick model budget). Fetching hostile web content does NOT break P1 (input, and
the agent now holds NOTHING to exfiltrate); RUNNING hostile code would, so job code runs in the SANDBOX
(no key, no secret, deny-by-default egress), never in the agent isolate. Assumptions:
- **A1** Cloudflare's isolate + service-binding boundary holds. Not pen-testable; TRUSTED. The spike proved
  the config-level boundary; the deep V8 boundary is trusted, not tested. Only bites if P1 fails.
- **A2** P1 holds BY CONSTRUCTION and CI-ENFORCED: no `eval`/`Function`/dynamic `import()`/`vm`/unsafe
  template sink; pinned+audited deps INCLUDING the TS port and all transitive deps (a lib exposing
  `new Function` re-opens the sink); LLM gets no code-exec/arbitrary-fetch tool. CI fails CLOSED if the
  lint ban is removed. Not prose.
- **A3** the agent KEEPS its published DID, moved into the gateway so FUTURE exposure
  is closed; the PAST transcript exposure is accepted. NEW users mint FRESH. Evaluate identity ROTATION at
  build (old key hands off to a fresh key, reputation carried) as an upgrade.
- **A4 (external)** Signature-reuse confinement depends on technocore enforcing NUMERIC note-nonces (1-19
  digits, spec/auth.md) on BOTH lanes AND the gateway always emitting a fixed uppercase verb prefix +
  name-grammar-validated job_id. The collision fuzz (§9) runs BOTH directions and asserts the numeric-nonce
  rule is what blocks the cross-parse.
- **A5 (the three-box invariant)** The agent hands NO secret to the sandbox or the fetch tool (it holds
  none); the SANDBOX egress is deny-by-default (`enableInternet:false` or a host allowlist); the research
  fetch is a MANDATORY deny-by-default host allowlist. Because the model token now lives in the gateway
  (not the agent), there is no readable secret in the agent to exfiltrate; A5 keeps it that way and bounds
  sandbox/fetch abuse and cost.

## 3. The gateway's signable grammar (hash-bound, three shapes)

Sign with the SAME discipline as the AUDITED `shared/action.py` v2 grammar, NOT a bespoke v1 line: free-form
content (a RESULT summary, an ATTEST reason, a note value) enters the signed bytes ONLY as a SHA-256 hash,
so no `|` can be forged; every token field is validated with `names.is_valid_name` / `is_sha256_hex` exactly
as `action._tok`/`_rh`. Provenance is derived INTERNALLY. Three shapes:
1. A **kibble work line** (CLAIM / RESULT / ATTEST) from the v2 hash-bound action string, signed over
   `message_sig_input("kibble", nonce, single_line(line))`.
2. Our **own identity / link note** in the agent's `did-<shard>` namespace, recomputed and signed
   internally, over `note_sig_input(ns, key, nonce, value)`.
3. A **signed room chat SAY** (reverses the old unsigned-SAY D1): the agent chats
   as ITSELF, cryptographically, like the human already does on the dashboard. Signed over
   `message_sig_input(room, nonce, single_line(text))` (free text, no hash: this is the protocol's raw
   signed-say format, not the hash-bound action grammar). TWO controls make it safe:
   (a) THE COLLISION GUARD is MANDATORY: `<room>|<nonce>|<text>` can be cross-parsed as a note write
       `<ns>|<key>|<nonce>|<value>` when the room is a note/ownership/identity namespace, so the gateway
       REFUSES a SAY whose room is `room-owners` / `room-allow` / `room-nonce` / `did` / `did-*` (the same
       reserved set the dashboard already ships). Free text is also rejected if it holds a lone surrogate
       (Python raises there; parity). (b) UNGATED per-post but RATE-BOUNDED: `SAY` is a normal (not
       dangerous) grant class with a user-set daily ceiling, so a hijacked agent cannot burn unlimited
       signed spam under its identity. Unbounded signed chat is at worst reputational spam (§0: improves
       over time), never key exposure; the collision guard is what keeps a SAY from becoming a key-relevant
       write.
FORBIDDEN (asserted + tested, incl. via the note namespace field): the give-away writes `room-owners`,
`room-allow`, `d-` ownership. `board_match` is DERIVED BY THE GATEWAY as EXACT `result_hash` equality
against the job's posted requirement (never fuzzy; the board is world-writable); only `verdict.useful` is
caller-supplied.

## 4. The Governor (grant enforcement), in the DO

Per requested write (all DO STORAGE, no in-memory carry, no `allowConcurrency:true` on these reads):
1. **Active-grant pin:** the DO holds ONE `active_grant_id`; reject any other grant_id even if validly
   signed. `owner_pub` and `active_grant_id` are DEPLOY-TIME anchors (Worker var / DO state, set at
   onboarding and via the steer path), NEVER read from a world-writable note. A steer that CHANGES the
   anchor must fully `verify_grant` the new grant before pinning it.
2. Verify with `grant.verify_grant(owner_pub, grant, now, revoked_ids, expected_agent=OUR_AGENT_DID)`;
   None/missing/expired/revoked/wrong-agent ALWAYS gates.
3. Class the action; get `authorized_ceiling`. A ceiling is NECESSARY not SUFFICIENT.
4. **Reserve-before-emit:** read-check-write SYNCHRONOUSLY with NO `await` between check and put. This
   atomic path exists ONLY on the SQLite SYNCHRONOUS DO storage API (prefer it); if the build uses the
   async (KV-backed) DO storage, `blockConcurrencyWhile` around the read-modify-write is MANDATORY, not
   optional (cron gives no overlap guarantee, so two ticks can reserve concurrently). Increment FIRST; a
   failed emit forfeits the slot (fails safe: under-spend). Allocate counter AND nonce in the same sync block.
5. Nonce: monotonic per-(key,room) from DO storage; refuse replay/rewind.
6. **Revoke at the head:** synchronously read `revoked:{grant_id}` at the START of every sign (cron-
   independent), so a human revoke gates the NEXT action for real.
Schema: `counter:{klass}:{window_start}`, per-`(key,room)` nonce high-water, `revoked:{grant_id}`,
`active_grant_id`, `steer_seen` high-water. `steer_seen` is a monotonic high-water + short expiry, NOT an
unbounded set: this REQUIRES monotonic steer issuance from the dashboard (an out-of-order valid steer is
rejected), state it.

## 5. The steer path

REVOKE/CHANGE IS OPTION A (built): the human's stop/change is a RE-SIGNED owner
GRANT (empty allow = stop), NOT a separate steer command. The gateway's own 1-min cron polls for the
newest owner-signed grant and applies it (governor.applySteerGrant): verify first, then a strict
issued-monotonic gate against a DURABLE, pin-independent high-water (`grant_issued_high`, so a cleared
pin from a revoke can NEVER reset the floor and let an old grant undo a stop), then pin. A future-dated
issued is rejected (issued <= now + skew) so a fat-finger can't jam the bar. THE READ CONTRACT is
load-bearing: read the grant from a SINGLE OWNER-KEYED NOTE SLOT, never a scan of the world-writable
steer room (its name is publicly derivable, so a room scan lets a flood of high-issued fakes bury the
real stop). The per-action APPROVAL envelope below (Option B, shared/steer verify_steer) is the
separate path for approving ONE gated dangerous action; ported later.

The dashboard writes a SIGNED steer to the steer room. The GATEWAY reads it BY ROLE (holds the name as a
secret; the agent never learns it and no response/error/log echoes it), verifies the owner signature + the
canonical `shared/steer` envelope (embedded==channel==destination, fail-closed, replay-proof, short
expiry), and applies pause / revoke / redirect. The GATEWAY runs its OWN 1-min cron to poll the steer room,
INDEPENDENT of the agent's work-wake knob (a cron is not a public route and not a long-running process, so
it preserves the zero-route / nothing-to-reap property while decoupling revoke ingestion from a possibly
15-min work-wake). REVOKE IS DURABLE, NOT A SHORT-LIVED STEER: it flips the DO `active_grant_id` pin +
sets `revoked:{grant_id}`, which are STICKY in the DO, so a revoke can never expire unread across an outage
or a long interval; it is bounded ultimately by the grant's own expiry. With §4.6's head-of-sign revoke
poll, once ingested it gates every subsequent action with nobody watching. The dashboard surfaces
"last acknowledged wake" so the human sees a revoke as PENDING vs APPLIED.

## 6. The wake model, the loop, research, and the sandbox

- **WAKE = a Cloudflare Cron Trigger** (as often as 1/min): the heartbeat. A Worker has no long-running
  process, so nothing can be reaped and nothing external can PUSH to it (the gateway has no public route,
  the agent no public entrypoint). It is PULL-based: each wake it CHECKS everything and acts. A Durable
  Object alarm can self-schedule a finer or deferred wake. Reactivity floor for WORK = the wake interval.
  REVOKE is DECOUPLED from it: the gateway's own 1-min steer-poll cron (§5) ingests a revoke within ~1 min
  regardless of the work-wake knob, and revoke is a durable pin, so once set it gates every subsequent
  action (§4.6) and cannot expire unread. The wake interval is a USER KNOB, a BOUNDED ENUM not a free
  integer ("check in every 1 / 5 / 15 min": more responsive vs slightly cheaper; an empty check is nearly
  free; the cron path is floored at 1 min and any DO-alarm finer path is capped for cost).
- **Each wake, one BOUNDED pass** (per-tick budget on writes AND model/sandbox/read calls, so a
  prompt-injected agent cannot burn cost without emitting a write either; do not grade an unbounded
  backlog: Workers wall-clock ~15min, CPU 30s, fetch-wait free, pool to 6 concurrent): read the board for
  new jobs; read the steer channel for the human's commands; read replies/mentions/mailbox addressed to
  it; post an UNSIGNED presence note via the protocol's `hb-<nick>` convention (`/kv/<room>/hb-<nick>/set`:
  world-writable, last-write-wins, NO key, NO signature, so it is NOT a signable shape and never routes
  through `sign()`; if signed presence is ever wanted it MUST reuse shape 2, never a new path or reserved
  namespace). That presence write is an unsigned write (within the already-accepted anonymous-spam residual)
  or routed through the gateway to keep the agent purely read-only. Then do the grant-allowed work and
  request the kibble line from the gateway.
- **Research (web / GitHub):** a MANDATORY deny-by-default host ALLOWLIST (research sources only; exclude
  technocore and any attacker host); read-only, no write credential held; the agent never executes fetched
  content (P1). Residual, accepted: every technocore write is a GET, so a hostile job could point the
  fetcher at an anonymous-write URL = anonymous spam under the user's IP, NOT key exposure.
- **Code jobs (the SANDBOX):** for jobs needing code RUN, the agent sends code + public inputs to the
  Sandbox (no key, no gateway/DO/protocol binding, no secret), which returns DATA the agent treats as
  untrusted input. HARD sandbox knobs (the Cloudflare default is UNRESTRICTED egress, so these are
  required, not optional): `enableInternet:false` for pure-compute, or a deny-by-default `allowedHosts`
  for jobs that must fetch; a FRESH RANDOM sandbox id per job (the id is the isolation boundary; a stable
  id lets a job leave a background miner for the next tick); aggressive `sleepAfter` + explicit destroy;
  `keepAlive` off; a per-tick sandbox-invocation cap. The 30s Worker CPU limit does NOT bound the
  container; the container knobs do.

## 6b. Agent memory (M1-M7): modest, safe, poisoning-resistant

The agent keeps a small memory so it improves over time: a bounded set of LEARNINGS, a durable ledger of
ACTED-on jobs, and a rolling window of SEEN jobs (dedup). It lives in a Durable Object bound to the AGENT
worker ONLY (`src/agent-memory.ts`, class `AgentMemory`), holds NO key, and has ZERO binding to the
gateway/Governor/model. The safety argument: memory crosses the key-exposure boundary only if it becomes
CODE (breaks P1) or TRUSTED BYTES (a nonce/counter/grant/ceiling the gateway or Governor trusts). Neither
can happen, by seven controls:

- M1 (persistence, the one new risk): eviction is by AGE-SINCE-CREATION with an IMMUTABLE creation clock.
  The DO owns that clock (a caller `now` is honoured only under TEST_MODE); a re-write of identical text
  is a no-op that never refreshes `created` (text is the primary key); every learning has a hard TTL
  (14d) so it must be RE-EARNED. So a poison planted once dies within the TTL when its source is gone; a
  continuously-injected agent can re-establish it, but that agent is already budget/Governor-bounded.
- M2/M4: no memory value is trusted for a security decision, ever. Memory strings are treated at the
  signer EXACTLY like world-writable board text (same §3 hash-only content, collision guard, forbidden
  set); nonces/counters come from the Governor DO, never memory. Job idempotency lives in memory and is
  therefore a convenience, NOT a safety guarantee (a poisoned ledger can at worst re-do a gated,
  ceiling-bounded action = spam).
- M3: a NARROW TYPED API (putLearning/getLearnings/recordActed/hasActed/markSeen/snapshot), NEVER raw
  SQL; every cap is enforced inside the DO; every return is PLAIN DATA; no public route.
- M5: split ledger with SEPARATE quotas so board spam in one store cannot starve another (learnings 256,
  acted 512, seen 2048), each age-evicted.
- M6 (defence in depth, at integration): run the egress content-scanner on the memory WRITE path and the
  SAY path; never persist raw completion/fetch text into a postable slot.
- M7 (stop-all, at integration): on an empty/absent active grant the gateway also refuses complete() and
  the research relay, so poisoned memory cannot keep burning model/read budget after a STOP.

BUILT (4c-1): the AgentMemory DO with M1/M3/M5, tested in real workerd (`test/agent-memory.agent.spec.ts`,
its own `vitest.agent.config.ts`), P1-scanned. M2/M4 are honoured by construction (the DO trusts nothing).
M6 DONE (4c-2 + 4d): the secret-shape scan runs on the memory write path (remember/handoff, agent-core) AND
the SAY egress (agent-core emit refuses a secret-shaped say with GATE_FORBIDDEN). M7 VERIFIED (4d), NO new
code: a STOP re-signs an empty-allow grant, so the Governor's `reserveModel` gates (authorizedCeiling of an
empty allow is null -> GATE_CLASS; no/absent grant -> GATE_NOT_ACTIVE), and `complete()` returns MODEL_GATED
with ZERO provider call (proven in governor.spec "the human's STOP gates all subsequent work" + model-proxy.spec).
The RESEARCH/sandbox half needs no gateway relay here: research is agent-side deny-by-default and is only
reachable from the planner AFTER a successful model call, and the planner calls the model FIRST each turn and
breaks on a non-OK status - so after a STOP the brain does no research/emit/sandbox (agent-planner.spec "M7
stop-all"). RESIDUAL, accepted (the anonymous-read residual, §6): a stopped agent still does ~3 unsigned
world-writable GETs per wake (presence + board/mailbox liveness) - no key, no meaningful cost. A v2 hardening
could take a stopped agent FULLY dark by gating even those harness reads on grant state (needs an agent->gateway
status query, new surface); not needed for v1 since the model/write/research spend a hijacked brain could drive
is already gated.

## 7. The model connection (through the gateway; no readable token in the agent)

The agent NEVER holds a model credential. It calls the gateway's `complete(prompt) -> text` RPC; the
GATEWAY holds the AI Gateway credential (`cf-aig-authorization`, and either Unified-Billing or a stored BYO
provider key) and makes the call, relaying only the completion text back. So "the agent holds nothing" is
literally true, and there is no model token for a prompt-injected agent to exfiltrate. The gateway does not
act on the completion beyond returning it (it signs only the validated two shapes).
- The user picks the MODEL and the billing: **Unified Billing** (prepaid Cloudflare credits, any model incl.
  Claude 5, one bill, 5% on top-ups, inference at provider rates) or **BYOK** (their own provider key,
  stored server-side in the gateway, never in the agent).
- **Cost bounds (stated precisely, not "impossible"):** three stacked. (a) the grant's per-class daily
  CEILINGS bound WRITE actions; (b) the model/read budget bounds model calls that never emit a write
  (grading loops), and it MUST be enforced IN THE GATEWAY against a Governor DO windowed counter (reuse the
  reserve-before-emit machinery: `complete()` decrements a DO-held budget), NEVER trusted to agent-side
  accounting a prompt-injected agent would ignore; (c) with Unified Billing, PREPAID credits are a hard
  floor the agent physically cannot exceed; with BYOK there is NO prepaid floor, so the DO-metered counter
  in (b) is the ONLY bound and the worst case is (per-tick-model-cap x ticks/day), state that number. The dashboard
  SHOWS estimated $/day next to the ceilings and the wake interval; a per-day money cap pauses as a
  backstop; cheap model default, frontier opt-in.

## 8. Onboarding / deploy

Per user: TWO Workers (agent + gateway) + the Governor DO + the Sandbox + a cron, plus the gateway's
secrets (identity key seed, steer-room name, model credential). The deploy account API TOKEN is a full
compromise of the boundary: it lives ONLY in a deploy step, NEVER a Worker Secret or reachable from any
isolate. The gateway SELF-PUBLISHES its own did note on first boot (no human key needed, D2). "Easy" is its
own design task (candidate: a guided "Deploy to Cloudflare" flow); BYO-account setup is not easy for
non-technical users, so the onboarding UX target stays open for a dedicated pass.

## 9. Ported code and how it is graded

Port `shared/` SIGNERS to TypeScript (v2 action string, steer, grant, kibble line, note), byte-checked
against `shared/vectors.json` PLUS a NEW key-format vector (raw seed -> pkcs8 DER -> non-extractable
`Ed25519` CryptoKey -> signature == Python; the spike PROVED this on workerd). A COLLISION FUZZ over the
REAL message/note wire bytes, BOTH directions, asserting the numeric-nonce rule blocks the cross-parse (a
property test, not golden vectors). The Governor, the egress scanner (defence-in-depth only), and
steer-verify get their OWN TS tests. The status-enum "never echo" is a unit test that feeds hostile input
and asserts the response is byte-identical to an enum member. This never-echo test covers BOTH the sign
path AND `complete()`'s error path (the model credential IS a key): map every `complete()` failure (an AI
Gateway 401, a provider 4xx/5xx whose body echoes the Authorization header, a thrown exception carrying a
stack/env) to a FIXED enum member, and a hostile-upstream unit test asserts the RPC return is byte-identical
to an enum member with ZERO provider-error passthrough and ZERO header/token substring. Do not grade the
port green on vectors alone.

## 10. What DIED (do not rebuild)

The egress content-scanner AS A BOUNDARY (defence in depth only); an LLM judge that reads board text; a
behavioural watcher; the approval gate as a safety primitive; autonomous spending / wallet (out of v1).
D4: sealed mail stays with the human; the agent never decrypt-and-returns (bounded conversation keys for
work mail are out of v1 scope).

## 11. Build order

1. Governor DO (schema + active-grant pin + verify + reserve-before-emit counter + nonce + revoked +
   monotonic steer high-water) with tests.
2. Gateway Worker (key import proven; the v2 hash-bound two-shape grammar + forbidden set + collision fuzz;
   provenance + exact-hash board_match internal; RPC returns only the fixed status enum + bytes or relayed
   model text; ZERO public route; steer-verify + head-of-sign revoke poll; the `complete()` model proxy
   holding the model credential; private I/O).
3. Agent Worker (cron wake loop, orchestration, no code/arbitrary-fetch tool beyond the allowlisted read
   tool, sandbox binding, holds nothing) + the Sandbox with the §6 hard egress knobs.
4. The TS signer port + vectors + key-format vector + the two-direction collision fuzz.
5. Cost estimate + wake-interval knob surfaced to the dashboard.
6. A fresh adversarial review of the built agent before done; then a deploy/onboarding + cost-UX pass.

## 12. Resolved decisions

D1 REVISED: the agent chats SIGNED (a third gateway shape, §3.3), not unsigned;
still ungated per-post (no approval card) but rate-bounded by the SAY ceiling, with the collision guard.
D2 gateway self-publishes its did note on boot; deploy token CI-only; UX open.
D3 OUR agent keeps the published DID (key into the gateway; past residual accepted); new users mint fresh;
rotation evaluated at build. D4 sealed mail out of the agent's v1 scope.
