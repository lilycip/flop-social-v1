"""Oracle for dashboard/server.py. Temp state only; a random high port; no real key.
Proves the guards (Host, Origin), key management, the pending cards, and above all the
approval flow: sign-what-you-saw, passphrase-per-approval, and a produced steer that
actually verifies under the human DID with full destination binding. ASCII only.
"""
import hashlib
import http.client
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as diddle  # noqa: E402
from shared import steer as S  # noqa: E402
import server  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


state = Path(tempfile.mkdtemp(prefix="dash_"))
httpd, dash = server.serve(state, host="127.0.0.1", port=0)
port = httpd.server_address[1]
dash.port = port
dash.origin = "http://127.0.0.1:%d" % port
threading.Thread(target=httpd.serve_forever, daemon=True).start()
GOODHOST = "127.0.0.1:%d" % port
ORIGIN = dash.origin


def req(method, path, host=None, origin=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    raw = json.dumps(body).encode("utf-8") if body is not None else None
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", host or GOODHOST)
    if origin:
        c.putheader("Origin", origin)
    if raw is not None:
        c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", str(len(raw)))
    c.endheaders(message_body=raw)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        return r.status, json.loads(data)
    except Exception:
        return r.status, data


s, _ = req("GET", "/api/status", host="evil.com:%d" % port)
check("GET with a foreign Host is refused", s == 403)
s, j = req("GET", "/api/status")
check("GET with the pinned Host is served", s == 200 and j.get("has_key") is False)
s, _ = req("POST", "/api/key/create", host="evil.com:%d" % port, origin=ORIGIN, body={"generate": True})
check("POST with a foreign Host is refused", s == 403)
s, _ = req("POST", "/api/key/create", origin=None, body={"generate": True})
check("POST with no Origin is refused", s == 403)
s, _ = req("POST", "/api/key/create", origin="http://evil.com", body={"generate": True})
check("POST with a foreign Origin is refused", s == 403)

s, j = req("POST", "/api/key/create", origin=ORIGIN, body={"generate": True})
check("create-key generate returns a did and a one-time passphrase", s == 200 and j["did"].startswith("did:key:z6Mk") and len(j.get("passphrase", "")) >= 20)
PW = j["passphrase"]
HDID = j["did"]
HPUB = diddle.pub_raw_from_did(HDID)
s, j = req("GET", "/api/status")
check("status now reports the key", j.get("has_key") is True and j.get("did") == HDID)
s, j = req("POST", "/api/key/create", origin=ORIGIN, body={"generate": True})
check("create-key refuses to overwrite an existing key", s == 400)
s, data = req("GET", "/api/key/export")
check("export returns the encrypted PEM", isinstance(data, bytes) and data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

BODY = "the delivery the human reads before voting"
RH = hashlib.sha256(BODY.encode()).hexdigest()
DEST = "mb-p-agentsteer01"
item = {"request_id": "r1", "verb": "ATTEST", "destination": DEST,
        "target": {"job_id": "job-42", "result_hash": RH, "delivery_body": BODY},
        "verdict": {"useful": True}}
(dash.pending / "r1.json").write_text(json.dumps(item), "utf-8")

s, j = req("GET", "/api/pending")
cards = j.get("pending", [])
check("pending lists the proposal as a card", len(cards) == 1 and cards[0]["request_id"] == "r1")
check("the card SHOWS the delivery body the human is vouching for",
      cards[0]["content"] == [["delivery being vouched for", BODY]])
COMMIT = cards[0]["action_commit"]

s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "r1", "commit": COMMIT})
check("approve with no passphrase is refused", s == 403 and j.get("need") == "passphrase")
s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "r1", "commit": "deadbeef", "passphrase": PW})
check("approve with a stale commit is refused (reread)", s == 409 and j.get("need") == "reread")
s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "r1", "commit": COMMIT, "passphrase": "wrong wrong wrong"})
check("approve with a wrong passphrase is refused", s == 403)
s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "r1", "commit": COMMIT, "passphrase": PW})
check("approve with the right commit and passphrase succeeds", s == 200 and j.get("ok") is True and "steer" in j)
steer = j["steer"]

ok = S.verify_steer(HPUB, steer, "ATTEST",
                    {"job_id": "job-42", "result_hash": RH, "delivery_body": BODY},
                    DEST, verdict={"useful": True}, now=time.time(), seen_nonces=set())
check("the produced steer verifies under the human DID at its destination", ok)
bad = S.verify_steer(HPUB, steer, "ATTEST",
                     {"job_id": "job-42", "result_hash": "b" * 64, "delivery_body": BODY},
                     DEST, verdict={"useful": True}, now=time.time(), seen_nonces=set())
check("the steer does NOT verify for a swapped delivery", not bad)
wrongdest = S.verify_steer(HPUB, steer, "ATTEST",
                           {"job_id": "job-42", "result_hash": RH, "delivery_body": BODY},
                           "mb-p-elsewhere", verdict={"useful": True}, now=time.time(), seen_nonces=set())
check("the steer does NOT verify at a different destination", not wrongdest)

s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "r1", "commit": COMMIT, "passphrase": PW})
check("an approved request cannot be approved again", s == 404)
s, j = req("GET", "/api/pending")
check("pending is empty after approval", j.get("pending") == [])

(dash.pending / "bad.json").write_text(json.dumps(
    {"request_id": "bad", "verb": "TRANSFER", "destination": DEST, "target": {"job_id": "j"}}), "utf-8")
s, j = req("GET", "/api/pending")
check("an unbindable proposal is listed as broken, not pending",
      any(b["request_id"] == "bad" for b in j.get("broken", [])) and j.get("pending") == [])
s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "bad", "commit": "x", "passphrase": PW})
check("approving an unbindable proposal is refused", s == 409)

(dash.pending / "sd.json").write_text(json.dumps(
    {"request_id": "sd", "verb": "SAY", "destination": "d-evil",
     "target": {"room": "lobby", "text": "hi"}}), "utf-8")
s, j = req("GET", "/api/pending")
check("a destination-inconsistent SAY is listed broken, not pending",
      any(b["request_id"] == "sd" for b in j.get("broken", [])))
s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": "sd", "commit": "x", "passphrase": PW})
check("approving a destination-inconsistent SAY is refused", s == 409)

import concurrent.futures  # noqa: E402
BODY3 = "concurrent delivery body"
RH3 = hashlib.sha256(BODY3.encode()).hexdigest()
item3 = {"request_id": "r3", "verb": "ATTEST", "destination": "mb-p-conc",
         "target": {"job_id": "job-9", "result_hash": RH3, "delivery_body": BODY3},
         "verdict": {"useful": True}}
(dash.pending / "r3.json").write_text(json.dumps(item3), "utf-8")
s, j = req("GET", "/api/pending")
c3 = next(c["action_commit"] for c in j["pending"] if c["request_id"] == "r3")
delivered_ids = []
dlock = threading.Lock()


def counting_writer(dest, steer, item):
    with dlock:
        delivered_ids.append(item["request_id"])
    return "posted"


dash.writer = counting_writer
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
    results = list(ex.map(lambda _: req("POST", "/api/approve", origin=ORIGIN,
                                        body={"request_id": "r3", "commit": c3, "passphrase": PW}),
                          range(2)))
codes = sorted(s for s, _ in results)
others = [c for c in codes if c != 200]
check("concurrent approve: exactly one 200", codes.count(200) == 1)
check("concurrent approve: the other is refused (409/404)", len(others) == 1 and others[0] in (404, 409))
check("concurrent approve DELIVERS EXACTLY ONCE", delivered_ids == ["r3"])
dash.writer = None

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    nonces = list(ex.map(lambda _: dash._next_nonce(), range(64)))
check("nonces are all distinct under concurrency", len(set(nonces)) == len(nonces))

for evil in ["../../owner", "..\\..\\owner", "r1/../r1", "a b", "x" * 65, ""]:
    s, j = req("POST", "/api/approve", origin=ORIGIN, body={"request_id": evil, "commit": "x", "passphrase": PW})
    check("traversal/invalid request_id %r is refused (404)" % evil, s == 404)

s, j = req("GET", "/api/status")
check("before any choice, setup_path is None (gate shut)", j.get("setup_path") is None)
s, j = req("POST", "/api/onboarding/choose", origin=ORIGIN, body={"path": "Z"})
check("an unknown setup path is refused (400)", s == 400)
s, j = req("GET", "/api/status")
check("a refused choice never opens the gate", j.get("setup_path") is None)
s, j = req("POST", "/api/onboarding/choose", origin=ORIGIN, body={})
check("a missing path is refused (400)", s == 400)
for bad in (True, 1, ["A"], {"x": "A"}, None):
    s, _ = req("POST", "/api/onboarding/choose", origin=ORIGIN, body={"path": bad})
    check("a non-string path %r is refused (400)" % (bad,), s == 400)
s, j = req("GET", "/api/status")
check("no type-confused path opened the gate", j.get("setup_path") is None)
s, j = req("POST", "/api/onboarding/choose", origin="http://evil.com", body={"path": "A"})
check("choose with a foreign Origin is refused (403)", s == 403)
s, j = req("GET", "/api/status")
check("a cross-origin choose never opens the gate", j.get("setup_path") is None)
s, j = req("POST", "/api/onboarding/choose", origin=ORIGIN, body={"path": "A"})
check("a valid choice is recorded and echoed", s == 200 and j.get("setup_path") == "A")
s, j = req("GET", "/api/status")
check("status now reports the chosen path", j.get("setup_path") == "A")
s, j = req("POST", "/api/onboarding/choose", origin=ORIGIN, body={"path": "B"})
check("re-choosing a different path is allowed (idempotent revisit)", s == 200 and j.get("setup_path") == "B")
dash.onboarding_path.write_text("{ not json", "utf-8")
s, j = req("GET", "/api/status")
check("an unreadable onboarding file reads as not chosen (fail closed)", j.get("setup_path") is None)
s, j = req("POST", "/api/onboarding/reset", origin=ORIGIN)
check("reset clears the choice back to None", s == 200 and j.get("setup_path") is None)

st2 = Path(tempfile.mkdtemp(prefix="dash2_"))
d2 = server.Dashboard(st2, host="127.0.0.1", port=0)
d2.onboarding_path.write_text(json.dumps({"path": "B"}), "utf-8")
check("a stale onboarding record reads before the new identity", d2._setup_path() == "B")
code2, _ = d2.create_key({"generate": True})
check("creating a new identity clears any prior onboarding choice", code2 == 200 and d2._setup_path() is None)

from shared import protocol as _P  # noqa: E402
from shared.canon import canon_int as _canon  # noqa: E402


class _FakePC:
    def __init__(self):
        self.notes = {}
        self.note_reads = {}
        self.read_error_keys = set()  # (ns,key) whose read simulates a transport failure ('error')

    def set_note(self, ns, key, value, confirm=False):
        self.notes[(ns, key)] = value
        return True, "stored"

    def get_note(self, ns, key):
        return self.note_reads.get((ns, key))

    def get_note_state(self, ns, key):
        if (ns, key) in self.read_error_keys:
            return "error", None
        if (ns, key) in self.note_reads:
            return "value", self.note_reads[(ns, key)]
        return "absent", None


dash.pc = _FakePC()
cns, ckey = dash._config_slot(HDID)
s, j = req("POST", "/api/cost/save", origin=ORIGIN,
           body={"model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "wake": 15, "passphrase": PW})
check("cost config signs and reports published", s == 200 and j.get("published") is True and j.get("wake") == 15)
env = json.loads(dash.pc.notes[(cns, ckey)])
ok = diddle.verify_by_did(HDID, env["sig"], _P.note_sig_input(cns, ckey, _canon(env["nonce"], "nonce"), env["payload"]))
check("the published config VERIFIES under the owner did at its own slot", ok)
check("the signed payload carries the chosen model and wake",
      json.loads(env["payload"]) == {"model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "wake": 15})
n1 = env["nonce"]
s, j = req("POST", "/api/cost/save", origin=ORIGIN,
           body={"model": "@cf/meta/llama-3.1-8b-instruct", "wake": 30, "passphrase": PW})
env2 = json.loads(dash.pc.notes[(cns, ckey)])
check("a re-sign RAISES the nonce (rollback guard)", env2["nonce"] > n1)
s, j = req("POST", "/api/cost/save", origin=ORIGIN, body={"model": "@cf/x/y", "wake": 7, "passphrase": PW})
check("a bad wake is refused (400)", s == 400)
s, j = req("POST", "/api/cost/save", origin=ORIGIN, body={"model": "@cf/x/y", "wake": True, "passphrase": PW})
check("a bool wake is refused (400)", s == 400)
s, j = req("POST", "/api/cost/save", origin=ORIGIN, body={"model": "bad model", "wake": 15, "passphrase": PW})
check("a malformed model id is refused (400)", s == 400)
s, j = req("POST", "/api/cost/save", origin=ORIGIN, body={"model": "@cf/x/y", "wake": 15, "passphrase": "wrong wrong wrong"})
check("a wrong passphrase is refused (403) and burns no nonce", s == 403)
env3 = json.loads(dash.pc.notes[(cns, ckey)])
check("the refused saves did not overwrite the last good signed config", env3["nonce"] == env2["nonce"])
# 'signed' now means the owner-signed config is ON THE SLOT and verifies (not just a local file), so
# mirror the landed write into the read-back fixture the way a real publish would leave it on the slot.
dash.pc.note_reads[(cns, ckey)] = dash.pc.notes[(cns, ckey)]
s, j = req("GET", "/api/cost")
check("cost status returns the current signed setting, choices and health",
      j.get("wake") == 30 and j.get("source") == "signed" and "wake_choices" in j and "health" in j)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

akey = Ed25519PrivateKey.generate()
adid = diddle.did_from_priv(akey)
dash.link_agent({"agent_did": adid, "nick": "jarvis"})
hns = diddle.did_note_ns(adid)
_, hshard = diddle.note_shard_key(adid)
hkey = hshard + "-health"
NOW = int(dash.clock())


def health_env(signer, status, ts, model="@cf/meta/llama-3.3-70b-instruct-fp8-fast"):
    payload = json.dumps({"status": status, "model": model, "ts": ts}, separators=(",", ":"))
    sig = diddle.sign_b64url(signer, _P.note_sig_input(hns, hkey, _canon(ts, "nonce"), payload))
    return json.dumps({"payload": payload, "nonce": ts, "sig": sig})


check("with no health note, the light is unknown/no-report", dash._model_health()["status"] == "unknown")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW)
check("a fresh OK health note (agent-signed) reads as working", dash._model_health()["status"] == "ok")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "MODEL_ERROR", NOW)
check("a fresh MODEL_ERROR reads as error (tells the owner to switch)", dash._model_health()["status"] == "error")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "MODEL_GATED", NOW)
check("a MODEL_GATED reads as paused, not error", dash._model_health()["status"] == "paused")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW - 3 * 3600)
check("a valid but OLD OK note reads as stale, never trusted as working", dash._model_health()["status"] == "stale")
spoof = Ed25519PrivateKey.generate()
dash.pc.note_reads[(hns, hkey)] = health_env(spoof, "OK", NOW)
check("an 'ok' signed by a NON-agent key is rejected -> unknown (no spoof)", dash._model_health()["status"] == "unknown")
good_sig_env = json.loads(health_env(akey, "OK", NOW))
tampered = json.dumps({"payload": json.dumps({"status": "OK", "model": "evil", "ts": NOW}),
                       "nonce": NOW, "sig": good_sig_env["sig"]})
dash.pc.note_reads[(hns, hkey)] = tampered
check("a tampered health payload does not verify -> unknown", dash._model_health()["status"] == "unknown")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW + 60)
check("a slightly-future ts (clock skew) reads working, not a false stale", dash._model_health()["status"] == "ok")
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW + 4000)
check("a far-future ts reads as stale, never working", dash._model_health()["status"] == "stale")

# --- The private activity feed: gateway-signed ring, dashboard verifies under the AGENT did ---
check("the activity slot derives identically to the gateway (cross-language parity)",
      dash._activity_slot_key("test-activity-secret") == "ae2263dd04a3f40054d13b7da39352fb01a762152")
_secret_a = dash._task_secret()
ans = diddle.did_note_ns(adid)
aslot = dash._activity_slot_key(_secret_a)


def activity_env(signer, ring, nonce=1):
    payload = json.dumps(ring, separators=(",", ":"))
    sig = diddle.sign_b64url(signer, _P.note_sig_input(ans, aslot, _canon(nonce, "nonce"), payload))
    return json.dumps({"payload": payload, "nonce": nonce, "sig": sig})


dash.pc.note_reads[(ans, aslot)] = activity_env(
    akey, [{"t": 100, "d": "said hi in general"}, {"t": 200, "d": "delivered result for job j1"}])
s, j = req("GET", "/api/activity")
check("the activity feed reads a ring the AGENT signed, in order",
      s == 200 and [it["d"] for it in j.get("items", [])] == ["said hi in general", "delivered result for job j1"])
_spoof_a = Ed25519PrivateKey.generate()
dash.pc.note_reads[(ans, aslot)] = activity_env(_spoof_a, [{"t": 1, "d": "forged what-it-did line"}])
s, j = req("GET", "/api/activity")
check("a ring signed by a NON-agent key is ignored (no forged 'what it did')",
      j.get("items") == [] and "error" in j)

import os as _os  # noqa: E402
M70 = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
# Clear the signed-config slot the earlier block left on the read-back fixture, so this tests the
# genuine no-signed-config path (otherwise the live slot, not the deploy record, would win).
dash.pc.note_reads.pop((cns, ckey), None)
# A REAL deploy record, bound to the linked agent (adid): the panel may trust it as 'deployed'.
dash._write_json(dash.deploy_state_path, {"status": "live", "our_did": adid, "model": M70, "wake": 5})
try:
    _os.remove(dash.cost_config_path)
except OSError:
    pass
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW)  # a fresh live report
s, j = req("GET", "/api/cost")
check("no signed config -> cost panel reads model+wake from the DEPLOY RECORD (not the default), source=deployed",
      j.get("model") == M70 and j.get("wake") == 5 and j.get("source") == "deployed")
check("running_model comes from a LIVE (ok) health report", j.get("running_model") == M70)
check("_current_wake falls back to the deployed wake for the health freshness window", dash._current_wake() == 5)
# A STALE report must not name a running model (could be hours old, or a replay of an old envelope).
dash.pc.note_reads[(hns, hkey)] = health_env(akey, "OK", NOW + 4000)
s, j = req("GET", "/api/cost")
check("a stale health report yields running_model=None (never a confidently-wrong model)", j.get("running_model") is None)
# A deploy record bound to a DIFFERENT agent must NOT masquerade as this agent's deployed model.
dash._write_json(dash.deploy_state_path, {"status": "live", "our_did": "did:key:zSomeOther", "model": M70, "wake": 5})
s, j = req("GET", "/api/cost")
check("a deploy record for a DIFFERENT agent is not trusted -> source unknown, no asserted model",
      j.get("source") == "unknown" and j.get("model") is None)
# No deploy record, agent still linked: we cannot claim a model -> unknown, never default-as-live.
try:
    _os.remove(dash.deploy_state_path)
except OSError:
    pass
s, j = req("GET", "/api/cost")
check("a linked agent with no deploy record -> source unknown (never a default shown as running)",
      j.get("source") == "unknown")
# Only with NO agent linked does the coded default show as a starting choice.
dash.unlink_agent()
s, j = req("GET", "/api/cost")
check("no agent linked at all -> the coded default is offered, source=default",
      j.get("source") == "default" and j.get("model") == server.DEFAULT_MODEL)

# A FLAKY config-slot read (transport error, NOT a genuine 'absent') must not let the panel assert the
# deployed model, and must tighten the freshness window to the shortest wake.
dash.pc.read_error_keys.add((cns, ckey))
s, j = req("GET", "/api/cost")
check("a flaky config-slot read -> source unknown, no asserted model (never the deployed model)",
      j.get("source") == "unknown" and j.get("model") is None)
check("a flaky config-slot read tightens the freshness wake to the minimum",
      dash._current_wake() == min(dash.WAKE_CHOICES))
dash.pc.read_error_keys.discard((cns, ckey))

httpd.shutdown()
sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
