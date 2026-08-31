"""Oracle for the PRIVATE TASK CHANNEL write side (dashboard/server.py: save_tasks / tasks_status).

The load-bearing property is CROSS-SIDE PARITY: an envelope this dashboard signs MUST verify exactly the
way the gateway's readOwnerTasks (agent/src/index.ts) reads it - same slot key, same signed bytes, same
payload shape - or the agent silently gets no tasks. So the core test RE-IMPLEMENTS the gateway's verify in
Python (independent of server.py's own helpers where it matters) and checks a real signed envelope passes it,
including that the slot key equals the exact 't'+sha256('flop-task-slot|'+secret)[:40] the TS derives. Also:
validation refuses an over-long / over-count / bad-schedule / bad-id / duplicate list; a wrong passphrase
signs nothing; an oversize envelope is refused BEFORE writing; a publish failure never loses the local save.
Temp dir; ASCII only.
"""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as D  # noqa: E402
from shared import protocol as P  # noqa: E402
from shared.canon import canon_int  # noqa: E402
import server as SRV  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class FakePC:
    """Records set_note calls (no network); can be told to fail to prove a publish failure never
    undoes the local save."""
    def __init__(self):
        self.notes = []
        self.fail = False

    def set_note(self, namespace, key, value, confirm=False):
        self.notes.append((namespace, key, value))
        if self.fail:
            raise RuntimeError("network down")
        return True, "ok " + namespace + "/" + key


def gateway_slot_key(secret):
    return "t" + hashlib.sha256(("flop-task-slot|" + secret).encode("utf-8")).hexdigest()[:40]


def gateway_read_tasks(owner_did, secret, note_value):
    """Verify + parse an envelope EXACTLY as the gateway does: derive ns+key, JSON-parse the envelope,
    verify the owner signature over note_sig_input(ns,key,canon(nonce),payload), then parse the payload
    array with the same bounds. Returns the task list, or [] on any failure (fail-closed)."""
    ns = D.did_note_ns(owner_did)
    key = gateway_slot_key(secret)
    try:
        env = json.loads(note_value)
    except Exception:
        return []
    if not isinstance(env, dict):
        return []
    payload, sig, nonce = env.get("payload"), env.get("sig"), env.get("nonce")
    if not isinstance(payload, str) or not isinstance(sig, str):
        return []
    try:
        nc = canon_int(nonce, "nonce")
    except Exception:
        return []
    if not D.verify_b64url(D.pub_raw_from_did(owner_did), sig, P.note_sig_input(ns, key, nc, payload)):
        return []
    try:
        arr = json.loads(payload)
    except Exception:
        return []
    if not isinstance(arr, list):
        return []
    out = []
    for t in arr[:8]:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") if isinstance(t.get("id"), str) else ""
        text = t.get("text") if isinstance(t.get("text"), str) else ""
        sched = t.get("schedule") if isinstance(t.get("schedule"), str) else "once"
        if tid and text:
            out.append({"id": tid[:48], "text": text[:240], "schedule": sched[:16]})
    return out


PW = "correct horse battery staple"
AGENT_PRIV, AGENT_DID = D.generate()
clk = Clock(1_700_000_000)
state = Path(tempfile.mkdtemp())
fake_pc = FakePC()
dash = SRV.Dashboard(str(state), clock=clk, protocol_client=fake_pc)
dash.ks.generate(PW)
owner_did = dash.ks.public_did()

VEC_SECRET = "super-secret-task-slot-seed-1234"
VEC_KEY = "t" + hashlib.sha256(b"flop-task-slot|super-secret-task-slot-seed-1234").hexdigest()[:40]
check("the slot key is 't'+sha256('flop-task-slot|'+secret)[:40], matching the gateway",
      dash._task_slot_key(VEC_SECRET) == VEC_KEY and VEC_KEY[0] == "t" and len(VEC_KEY) == 41)

check("sending tasks with no agent linked is refused 400",
      dash.save_tasks({"tasks": [{"id": "presence", "text": "keep presence", "schedule": "hourly"}],
                       "passphrase": PW})[0] == 400)

dash.link_agent({"agent_did": AGENT_DID, "nick": "jarvis"})

good = [{"id": "presence", "text": "keep presence", "schedule": "hourly"},
        {"id": "daily-post", "text": "add one real line to an active room", "schedule": "daily"}]
check("a bad schedule is refused",
      dash.save_tasks({"tasks": [{"id": "x", "text": "y", "schedule": "fortnightly"}], "passphrase": PW})[0] == 400)
check("a bad id (spaces) is refused",
      dash.save_tasks({"tasks": [{"id": "bad id", "text": "y", "schedule": "once"}], "passphrase": PW})[0] == 400)
check("an empty text is refused",
      dash.save_tasks({"tasks": [{"id": "x", "text": "   ", "schedule": "once"}], "passphrase": PW})[0] == 400)
check("a duplicate id is refused",
      dash.save_tasks({"tasks": [{"id": "x", "text": "a", "schedule": "once"},
                                 {"id": "x", "text": "b", "schedule": "once"}], "passphrase": PW})[0] == 400)
check("more than MAX_TASKS is refused",
      dash.save_tasks({"tasks": [{"id": "t%d" % i, "text": "do", "schedule": "once"} for i in range(9)],
                       "passphrase": PW})[0] == 400)
check("an over-long task text is refused",
      dash.save_tasks({"tasks": [{"id": "x", "text": "z" * 241, "schedule": "once"}], "passphrase": PW})[0] == 400)

before = len(fake_pc.notes)
check("a wrong passphrase is refused 403", dash.save_tasks({"tasks": good, "passphrase": "wrong"})[0] == 403)
check("a wrong passphrase published nothing", len(fake_pc.notes) == before)

code, out = dash.save_tasks({"tasks": good, "passphrase": PW})
check("save_tasks succeeds", code == 200 and out["ok"] and out["count"] == 2 and out["published"] is True)
ns_written, key_written, value_written = fake_pc.notes[-1]
secret = dash._task_secret()
check("published to the owner note namespace + the derived secret slot key",
      ns_written == D.did_note_ns(owner_did) and key_written == gateway_slot_key(secret))
read_back = gateway_read_tasks(owner_did, secret, value_written)
check("the gateway verify+parse reproduces EXACTLY the tasks we signed", read_back == good)

env = json.loads(value_written)
env2 = dict(env)
env2["payload"] = json.dumps([{"id": "evil", "text": "swapped in", "schedule": "hourly"}], separators=(",", ":"))
check("a tampered payload fails the gateway verify -> []", gateway_read_tasks(owner_did, secret, json.dumps(env2)) == [])

check("reading with the WRONG secret yields [] (slot-bound)",
      gateway_read_tasks(owner_did, "a-totally-different-secret", value_written) == [])

fake_pc.fail = True
code, out = dash.save_tasks({"tasks": good, "passphrase": PW})
check("a publish failure still returns 200 with published False", code == 200 and out["published"] is False)
saved = json.loads((state / "tasks.json").read_text("utf-8"))
check("the local tasks.json kept the saved list even though the publish failed",
      [t["id"] for t in saved["tasks"]] == ["presence", "daily-post"])
fake_pc.fail = False

st = dash.tasks_status()[1]
check("tasks_status returns the saved list", [t["id"] for t in st["tasks"]] == ["presence", "daily-post"])
check("tasks_status offers the seeded playbook", any(p["id"] == "presence" for p in st["playbook"]))
check("tasks_status lists the four schedules", st["schedules"] == ["once", "hourly", "daily", "weekly"])
check("tasks_status surfaces the TASK_SECRET + a default model for deploy",
      st["deploy"]["task_secret"] == secret and st["deploy"]["model"] and st["deploy"]["model_choices"])

check("a bad model id is refused", dash.save_config({"model": "no spaces allowed here"})[0] == 400)
check("a valid model id saves", dash.save_config({"model": "@cf/meta/llama-3.1-8b-instruct"})[0] == 200)
check("the saved model comes back in tasks_status",
      dash.tasks_status()[1]["deploy"]["model"] == "@cf/meta/llama-3.1-8b-instruct")

big_mb = [{"id": "t%d" % i, "text": "每" * 240, "schedule": "daily"} for i in range(8)]
before_big = len(fake_pc.notes)
check("an over-size MULTIBYTE playbook is refused (byte gate, not char gate)",
      dash.save_tasks({"tasks": big_mb, "passphrase": PW})[0] == 400)
check("the refused over-size playbook published nothing", len(fake_pc.notes) == before_big)

mb_ok = [{"id": "cjk", "text": "每天发一条", "schedule": "daily"},
         {"id": "emoji", "text": "say hi ✨", "schedule": "once"}]
code, _ = dash.save_tasks({"tasks": mb_ok, "passphrase": PW})
_, _, mb_value = fake_pc.notes[-1]
check("a small multibyte playbook signs + verifies the gateway way", code == 200 and
      gateway_read_tasks(owner_did, dash._task_secret(), mb_value) == mb_ok)

swept = [{"id": "sweep", "text": "hello‮world", "schedule": "once"}]
dash.save_tasks({"tasks": swept, "passphrase": PW})
_, _, sw_value = fake_pc.notes[-1]
out_sw = gateway_read_tasks(owner_did, dash._task_secret(), sw_value)
check("a bidi-override char in task text is swept before signing (not stored raw)",
      len(out_sw) == 1 and "‮" not in out_sw[0]["text"] and out_sw[0]["text"] == "hello world")

import tempfile as _tf
state2 = Path(_tf.mkdtemp())
d2 = SRV.Dashboard(str(state2), clock=clk, protocol_client=FakePC())
d2.ks.generate(PW)
_, ad2 = D.generate(); d2.link_agent({"agent_did": ad2, "nick": "j2"})
(state2 / "task_secret.txt").write_text("   ", encoding="utf-8")
check("save_tasks refuses (500) when the task-secret file is present but unreadable/empty",
      d2.save_tasks({"tasks": good, "passphrase": PW})[0] == 500)
st2 = d2.tasks_status()[1]
check("tasks_status flags the corrupt secret instead of minting a fresh one",
      st2["deploy"]["task_secret"] is None and st2["deploy"]["secret_error"])
check("the corrupt secret file was NOT overwritten with a new one",
      (state2 / "task_secret.txt").read_text("utf-8").strip() == "")

sys.stdout.write("----\n" + ("ALL PASS\n" if not FAILS else ("FAILED: %d\n" % len(FAILS))))
sys.exit(1 if FAILS else 0)
