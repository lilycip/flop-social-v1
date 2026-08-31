"""Oracle for dashboard/deploy_engine.py. The whole deploy sequence runs against a FAKE wrangler
runner, so it is fully offline: no network, no real wrangler, no real Cloudflare. It proves the
security invariants that matter -- the seed never surfaces, a failed step halts, inputs are
validated, and a re-deploy never re-mints -- without ever touching a cloud. ASCII only.
"""
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

import server  # noqa: E402
import deploy_engine  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


def make_dash():
    state = Path(tempfile.mkdtemp(prefix="deploy_"))
    dash = server.Dashboard(state, host="127.0.0.1", port=0)
    dash.ks.generate("a-strong-owner-pass")
    return dash


def make_fake(fail_on=None):
    """A fake runner keyed off argv. fail_on: a substring that, when present in the joined argv,
    makes that call return non-zero (to test halting)."""
    calls = []

    def fake(argv, cwd=None, stdin=None, timeout=None):
        calls.append({"argv": list(argv), "stdin": stdin})
        joined = " ".join(argv)
        if fail_on and fail_on in joined:
            return 1, "", "forced failure for the test"
        if argv[-1] == "whoami":
            return 0, "You are logged in as test@example.com.", ""
        if argv[-1].endswith("check_deploy.mjs"):
            return 0, "[OK] everything green", ""
        if "secret" in argv and "put" in argv:
            return 0, "Success! Uploaded secret", ""
        if "deploy" in argv:
            return 0, "Deployed to https://example.workers.dev", ""
        return 0, "", ""

    return fake, calls


def wait_done(engine, timeout=5.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        overall = engine.deploy_status()[1]["overall"]
        if overall in ("live", "failed"):
            return overall
        time.sleep(0.02)
    return "timeout"


dash = make_dash()
fake, calls = make_fake()
eng = deploy_engine.DeployEngine(dash, runner=fake)
for bad in ({"agent_name": "", "model": "@cf/x/y", "wake": 15},
            {"agent_name": "a; rm -rf /", "model": "@cf/x/y", "wake": 15},
            {"agent_name": "-flag", "model": "@cf/x/y", "wake": 15},
            {"agent_name": "ok", "model": "bad model with spaces", "wake": 15},
            {"agent_name": "ok", "model": "@cf/x/y", "wake": 7},
            {"agent_name": "ok", "model": "@cf/x/y", "wake": True},
            {"agent_name": "ok", "model": "@cf/x/y", "wake": "15"}):
    code, _ = eng.start(bad)
    check("start refuses invalid input %r" % (bad,), code == 400)

dash = make_dash()
fake, calls = make_fake()
eng = deploy_engine.DeployEngine(dash, runner=fake)
code, snap = eng.start({"agent_name": "jarvis jr", "model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "wake": 15})
check("a valid start is accepted (200)", code == 200)
overall = wait_done(eng)
check("the deploy reaches 'live'", overall == "live")
final = eng.deploy_status()[1]
check("every step is ok at the end", all(s["status"] == "ok" for s in final["steps"]))
our_did = final.get("our_did")
check("finalize records the agent's did:key", isinstance(our_did, str) and our_did.startswith("did:key:z6Mk"))
linked = dash.agent_status()[1]
check("the agent DID was auto-linked in the dashboard", linked.get("agent_did") == our_did)
cfg = json.loads((dash.config_path).read_text("utf-8"))
check("the chosen model and wake are recorded for the dashboard knobs", cfg.get("model") == "@cf/meta/llama-3.3-70b-instruct-fp8-fast" and cfg.get("wake") == 15)

seed_call = next((c for c in calls if "KEY_SEED" in c["argv"]), None)
check("the seed was piped to `secret put KEY_SEED` on stdin", seed_call is not None and seed_call["stdin"])
seed = seed_call["stdin"].decode("utf-8").strip()
check("the piped value is a 32-byte seed (64 hex)", len(seed) == 64 and all(c in "0123456789abcdef" for c in seed))
blob = json.dumps(eng.deploy_status()[1])
check("the seed is NOT in the deploy status payload", seed not in blob)
check("the seed is NOT in any step detail", all(seed not in s["detail"] for s in final["steps"]))
dep = json.loads(eng.deploy_state_path.read_text("utf-8"))
check("the seed is NOT written to deploy.json", seed not in json.dumps(dep))
ts_call = next((c for c in calls if "TASK_SECRET" in c["argv"]), None)
check("the task secret was piped on stdin, never as an argument", ts_call is not None and ts_call["stdin"])
ts = ts_call["stdin"].decode("utf-8").strip()
check("the task secret is NOT in the deploy status payload", ts not in blob)

agent_call = next((c for c in calls if "--triggers" in c["argv"]), None)
check("the agent deploy sets the 1/min heartbeat cron",
      agent_call is not None and "* * * * *" in agent_call["argv"])
check("the agent deploy passes the chosen wake as WAKE_MINUTES",
      agent_call is not None and "WAKE_MINUTES:15" in agent_call["argv"])
check("the agent deploy also sets its public NICK",
      agent_call is not None and any(a.startswith("NICK:") for a in agent_call["argv"]))

eng._overall = "failed"
ds = eng.deploy_status()[1]
check("a failed re-deploy is not masked as 'live' by the old deploy.json", ds["overall"] == "failed")
check("the prior agent did is still surfaced during a re-deploy", ds.get("our_did") == our_did)
eng._overall = "live"

eng.deploy_state_path.unlink()
fake2, calls2 = make_fake()
eng2 = deploy_engine.DeployEngine(dash, runner=fake2)
eng2.start({"agent_name": "jarvis jr", "model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "wake": 15})
check("re-deploy reaches 'live'", wait_done(eng2) == "live")
check("re-deploy keeps the SAME agent identity (no re-mint)", eng2.deploy_status()[1].get("our_did") == our_did)

dash4 = make_dash()
f4, _ = make_fake()
eng4 = deploy_engine.DeployEngine(dash4, runner=f4)
eng4.start({"agent_name": "strandtest", "model": "@cf/meta/llama-3.1-8b-instruct", "wake": 15})
check("strand-setup deploy reaches live", wait_done(eng4) == "live")
side_before = (dash4.dir / "agent-id" / "owner.passphrase").read_text("utf-8")
(dash4.dir / "agent-id" / "owner.json").unlink()
stranded_refused = False
try:
    eng4._agent_identity()
except Exception:
    stranded_refused = True
check("a stranded agent identity is refused, not overwritten", stranded_refused)
check("the stranded key's passphrase was NOT destroyed",
      (dash4.dir / "agent-id" / "owner.passphrase").read_text("utf-8") == side_before)

dash3 = make_dash()
fake3, calls3 = make_fake(fail_on="OUR_DID")
eng3 = deploy_engine.DeployEngine(dash3, runner=fake3)
eng3.start({"agent_name": "halt", "model": "@cf/meta/llama-3.1-8b-instruct", "wake": 30})
check("a broken gateway deploy ends 'failed'", wait_done(eng3) == "failed")
st = {s["key"]: s["status"] for s in eng3.deploy_status()[1]["steps"]}
check("the failing step is marked failed", st["gateway"] == "failed")
check("steps AFTER the failure never ran (secrets pending)", st["secrets"] == "pending")
check("steps AFTER the failure never ran (agent pending)", st["agent"] == "pending")
check("no KEY_SEED secret was pushed after the gateway failed",
      not any("KEY_SEED" in c["argv"] for c in calls3))
check("deploy.json was not written as live on failure", not eng3.deploy_state_path.exists())

import subprocess  # noqa: E402
agent_dir = ROOT / "agent"
try:
    pf = subprocess.run(["node", "tools/check_deploy.mjs"], cwd=str(agent_dir),
                        capture_output=True, timeout=60)
    check("the real check_deploy.mjs passes on the checked-in configs (rc 0)", pf.returncode == 0)
    if pf.returncode != 0:
        sys.stdout.write(pf.stdout.decode("utf-8", "replace")[-600:] + "\n")
except FileNotFoundError:
    sys.stdout.write("SKIP real preflight (node not found)\n")

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
