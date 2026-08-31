"""Oracle for shared/. Proves the wire contract holds and, above all, that the
partial-binding class of hole is closed: an approval binds the COMPLETE action, so
swapping any semantic field (result_hash included) invalidates it. ASCII only, no
network, no real keys touched.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import names, did, protocol, action, steer  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


check("name grammar accepts a normal room", names.is_valid_name("lobby"))
check("name grammar rejects a slash", not names.is_valid_name("a/b"))
check("name grammar rejects empty", not names.is_valid_name(""))
check("name grammar rejects 49 chars", not names.is_valid_name("a" * 49))
check("mb-p- is a private mailbox", names.room_class("mb-p-9f2c") == "mailbox_private")
check("mb- is a mailbox", names.room_class("mb-team") == "mailbox")
check("p- is private", names.room_class("p-9f2c") == "private")
check("d- is ownable", names.room_class("d-jobs") == "ownable")
check("lobby is open", names.room_class("lobby") == "open")
check("p- name is a bearer secret", names.name_is_bearer_secret("p-9f2c"))
check("lobby name is not a bearer secret", not names.name_is_bearer_secret("lobby"))
check("mailbox write needs a signature", names.write_requires_signature("mb-team"))
check("open write needs no signature", not names.write_requires_signature("lobby"))

priv, d = did.generate()
check("did looks like did:key:z6Mk...", d.startswith("did:key:z6Mk"))
check("pub round-trips through the did", did.pub_raw_from_did(d) == did.pub_raw(priv))
msg = b"the exact bytes"
sig = did.sign_b64url(priv, msg)
check("signature is 86-char unpadded base64url", len(sig) == 86 and "=" not in sig)
check("signature verifies by raw pub", did.verify_b64url(did.pub_raw(priv), sig, msg))
check("signature verifies by did", did.verify_by_did(d, sig, msg))
check("signature fails on tampered message", not did.verify_by_did(d, sig, b"other bytes"))
priv2, d2 = did.generate()
check("signature fails under a different key", not did.verify_by_did(d2, sig, msg))
check("verify never raises on garbage sig", did.verify_b64url(did.pub_raw(priv), "!!!!", msg) is False)
fp = did.fingerprint(d)
check("fingerprint is 16 lowercase hex", len(fp) == 16 and fp == fp.lower())
check("did note namespace is did-<shard>", did.did_note_ns(d) == "did-" + fp[:2])

check("message sig input is room|nonce|text",
      protocol.message_sig_input("lobby", 7, "hi") == b"lobby|7|hi")
check("note sig input is ns|key|nonce|value",
      protocol.note_sig_input("did-94", "abc", 3, "val") == b"did-94|abc|3|val")
u = protocol.url_say("lobby", "alice", "a/b c")
check("say URL percent-encodes text (no raw slash escapes the segment)",
      "/say/alice/a%2Fb%20c" in u)
u2 = protocol.url_say_signed("mb-team", d, sig, 9, "hi there")
check("say-signed URL encodes its text segment (space -> %20)",
      "/say-signed/" in u2 and "/9/hi%20there" in u2)
msgs, last = protocol.parse_room_json({"messages": [{"from": "~x", "seq": 1, "text": "hi"}], "last_seq": 4})
check("parse_room_json returns messages and last_seq", len(msgs) == 1 and last == 4)
check("parse_room_json is defensive on garbage", protocol.parse_room_json("nope") == ([], None))
check("cursor-free read has no since (true-tail read)", "since=" not in protocol.url_room_read("lobby"))
check("cursor read carries since and wait", "since=4" in protocol.url_room_read("lobby", 4, 10))

RH = "a" * 64
RH2 = "b" * 64
a_useful = action.action_string("ATTEST", {"job_id": "job-1", "result_hash": RH}, {"useful": True})
a_not = action.action_string("ATTEST", {"job_id": "job-1", "result_hash": RH}, {"useful": False})
a_swapped = action.action_string("ATTEST", {"job_id": "job-1", "result_hash": RH2}, {"useful": True})
check("ATTEST binds result_hash in the string", ("rh:" + RH) in a_useful)
check("flipping the verdict changes the action", a_useful != a_not)
check("SWAPPING THE DELIVERY changes the action (the old hole, closed)", a_useful != a_swapped)
raised = False
try:
    action.action_string("TRANSFER", {"job_id": "job-1"}, None)
except ValueError:
    raised = True
check("an unknown verb RAISES (no under-bound fallback)", raised)
raised = False
try:
    action.action_string("ATTEST", {"job_id": "job-1", "result_hash": "short"}, {"useful": True})
except ValueError:
    raised = True
check("a non-sha256 result_hash is refused", raised)
raised = False
try:
    action.action_string("ATTEST", {"job_id": "job/../etc", "result_hash": RH}, {"useful": True})
except ValueError:
    raised = True
check("a job_id outside the name grammar is refused", raised)
say1 = action.action_string("SAY", {"room": "lobby", "text": "hello"}, None)
say2 = action.action_string("SAY", {"room": "lobby", "text": "hello world"}, None)
check("changing SAY text changes the action", say1 != say2)
check("SAY text enters only as a hash (no raw text in the string)", "hello" not in say1)
raised = False
try:
    action.action_string("ATTEST", {"job_id": "job-1", "result_hash": RH}, {"useful": "false"})
except ValueError:
    raised = True
check("a non-boolean verdict.useful is refused (no 'false' -> useful)", raised)
raised = False
try:
    action.action_string("SAY", {"room": "lobby", "text": ["not", "a", "string"]}, None)
except ValueError:
    raised = True
check("a non-string content field is refused", raised)

sc = action.bound_content("SAY", {"room": "lobby", "text": "the real message"})
check("bound_content returns the full SAY text to display", sc == [("message text", "the real message")])
nc = action.bound_content("NOTE_WRITE", {"namespace": "did-94", "key": "abc", "value": "did:key:zEVIL"})
check("bound_content returns the full NOTE value (the DID-note payload is shown)",
      nc == [("note value", "did:key:zEVIL")])
body = "the delivery the human is voting on"
import hashlib as _h
bh = _h.sha256(body.encode()).hexdigest()
ac = action.bound_content("ATTEST", {"job_id": "job-1", "result_hash": bh, "delivery_body": body})
check("ATTEST bound_content shows the delivery body when it hashes to result_hash",
      ac == [("delivery being vouched for", body)])
raised = False
try:
    action.bound_content("ATTEST", {"job_id": "job-1", "result_hash": RH})
except ValueError:
    raised = True
check("ATTEST approval REFUSES to render without the delivery body", raised)
raised = False
try:
    action.bound_content("ATTEST", {"job_id": "job-1", "result_hash": RH, "delivery_body": "wrong body"})
except ValueError:
    raised = True
check("ATTEST refuses a delivery body that does NOT hash to result_hash", raised)
check("CLAIM binds no free content", action.bound_content("CLAIM", {"job_id": "job-1"}) == [])
check("SAY embeds its room as destination", action.embedded_destination("SAY", {"room": "lobby"}) == "lobby")
check("NOTE_WRITE embeds its namespace", action.embedded_destination("NOTE_WRITE", {"namespace": "did-94"}) == "did-94")
check("ATTEST embeds no destination (channel carries it)", action.embedded_destination("ATTEST", {"job_id": "j"}) is None)

vfile = json.loads((ROOT / "shared" / "vectors.json").read_text("utf-8"))
check("vectors.json version matches action.VERSION", vfile["version"] == action.VERSION)
all_match = True
for v in vfile["vectors"]:
    got = action.action_string(v["verb"], v["target"], v["verdict"])
    gotc = action.action_commit(v["verb"], v["target"], v["verdict"])
    if got != v["action_string"] or gotc != v["action_commit"]:
        all_match = False
        sys.stdout.write("   drift: %s\n     want %r\n     got  %r\n" % (v["verb"], v["action_string"], got))
check("every golden vector reproduces exactly (cross-language contract)", all_match)

hpriv, hdid = did.generate()
hpub = did.pub_raw(hpriv)
DEST = "mb-p-deadbeef"
ATT_T = {"job_id": "job-1", "result_hash": RH}
ATT_V = {"useful": True}
ATT_T2 = {"job_id": "job-1", "result_hash": RH2}
act = action.action_string("ATTEST", ATT_T, ATT_V)
env = steer.build_steer(hpriv, DEST, act, nonce=1, expiry=1000)
seen = set()


def vs(env_, verb, target, dest, verdict=None, now=500, seen_nonces=None):
    return steer.verify_steer(hpub, env_, verb, target, dest, verdict=verdict,
                              now=now, seen_nonces=seen_nonces if seen_nonces is not None else set())


check("a valid steer verifies for its re-derived action at its destination",
      vs(env, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=seen))
check("the same nonce is now refused (replay)",
      not vs(env, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=seen))
env_str = dict(env); env_str["nonce"] = "1"
check("Finding 2: replay via a differently-TYPED nonce is refused",
      not vs(env_str, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=seen))
raised = False
try:
    steer.canon_int("1\n", "nonce")
except ValueError:
    raised = True
check("New-1: canon_int refuses a trailing newline", raised)
env_nl = dict(env); env_nl["nonce"] = "1\n"
check("New-1: a newline nonce is refused at verify",
      not vs(env_nl, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=set()))
raised = False
try:
    steer.build_steer(hpriv, DEST, act, nonce="01", expiry=1000)
except ValueError:
    raised = True
check("a non-canonical nonce (leading zero) is refused at build", raised)
env_lz = dict(env); env_lz["nonce"] = "01"
check("a non-canonical nonce is refused at verify",
      not vs(env_lz, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=set()))
BIG = "1234567890123456789"
env_big = steer.build_steer(hpriv, DEST, act, nonce=BIG, expiry="9999999999")
check("a 19-digit nonce is stored as a string", env_big["nonce"] == BIG and isinstance(env_big["nonce"], str))
check("a 19-digit-nonce steer verifies", vs(env_big, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=set()))
env2 = steer.build_steer(hpriv, DEST, act, nonce=2, expiry=1000)
check("a steer does not authorize a swapped delivery (re-derived action differs)",
      not vs(env2, "ATTEST", ATT_T2, DEST, ATT_V, seen_nonces=set()))
check("Finding 3: a valid steer applied to the WRONG destination is refused",
      not vs(env2, "ATTEST", ATT_T, "mb-p-elsewhere", ATT_V, seen_nonces=set()))
check("Finding 3: a missing destination is a reject, not a trust",
      not vs(env2, "ATTEST", ATT_T, None, ATT_V, seen_nonces=set()))
say_t = {"room": "lobby", "text": "hi"}
say_act = action.action_string("SAY", say_t, None)
env_taut = steer.build_steer(hpriv, "mb-p-human", say_act, nonce=7, expiry=1000)
check("New-2: even with destination==channel, action's embedded room != channel is refused",
      not vs(env_taut, "SAY", say_t, env_taut["channel"], seen_nonces=set()))
env_ok = steer.build_steer(hpriv, "lobby", say_act, nonce=8, expiry=1000)
check("a SAY where embedded==channel==destination verifies",
      vs(env_ok, "SAY", say_t, "lobby", seen_nonces=set()))
env3 = steer.build_steer(hpriv, DEST, act, nonce=3, expiry=100)
check("an expired steer is refused", not vs(env3, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=set()))
check("no clock is a reject, not a trust", not vs(env2, "ATTEST", ATT_T, DEST, ATT_V, now=None, seen_nonces=set()))
check("no replay store is a reject, not a trust",
      not steer.verify_steer(hpub, env2, "ATTEST", ATT_T, DEST, verdict=ATT_V, now=500, seen_nonces=None))
wrongpriv, _ = did.generate()
env5 = steer.build_steer(wrongpriv, DEST, act, nonce=5, expiry=1000)
check("a steer signed by a different key is refused", not vs(env5, "ATTEST", ATT_T, DEST, ATT_V, seen_nonces=set()))
check("verify never raises on an unbuildable target",
      vs(env2, "ATTEST", {"job_id": "job-1"}, DEST, ATT_V, seen_nonces=set()) is False)
raised = False
try:
    steer.build_steer(hpriv, "", act, nonce=6, expiry=1000)
except ValueError:
    raised = True
check("building a steer with no channel is refused", raised)

for bad in (["x"], "abc", 5, 3.14):
    check("verify_steer rejects (not raises) on non-dict target %r" % (bad,),
          vs(env2, "ATTEST", bad, DEST, ATT_V, seen_nonces=set()) is False)
check("verify_steer rejects on non-dict verdict",
      steer.verify_steer(hpub, env2, "ATTEST", ATT_T, DEST, verdict=["x"], now=500, seen_nonces=set()) is False)
raised = False
try:
    action.action_string("ATTEST", ["not", "a", "dict"], {"useful": True})
except ValueError:
    raised = True
check("action_string raises ValueError (not AttributeError) on non-dict target", raised)
raised = False
try:
    action.action_string("ATTEST", {"job_id": "j", "result_hash": RH}, ["x"])
except ValueError:
    raised = True
check("action_string raises ValueError on non-dict verdict", raised)

view = action.approval_view("SAY", {"room": "lobby", "text": "hello"}, None)
check("approval_view binds and shows from the SAME target",
      view["content"] == [("message text", "hello")]
      and view["action_string"] == action.action_string("SAY", {"room": "lobby", "text": "hello"}, None))

sv = vfile.get("steer_vectors", [])
sv_ok = len(sv) > 0
for s in sv:
    got = steer.steer_message(s["channel"], s["action_string"], s["nonce"], s["expiry"]).decode("utf-8")
    if got != s["steer_message"]:
        sv_ok = False
        sys.stdout.write("   steer drift: want %r got %r\n" % (s["steer_message"], got))
check("every golden steer message reproduces exactly (incl. 19-digit nonce)", sv_ok)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
