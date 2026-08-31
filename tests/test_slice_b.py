"""Oracle for Slice B: the protocol client (dashboard/protocol_client.py) and the server's
signed-say path (dashboard/server.py Dashboard.say), both with INJECTED http and no network.
Proves: rooms/messages parse and normalise defensively; a signed verified writer is told apart
from a self-asserted ~nick; the server signs the SWEPT text (single_line) over the exact
<room>|<nonce>|<text> the wire stores, loads the key for one signature only, and a wrong
passphrase posts nothing. Temp state dir only; ASCII except one deliberate unicode message.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as D  # noqa: E402
from shared import protocol as P  # noqa: E402
import protocol_client as PC  # noqa: E402
import server as SRV  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


ROOMS_BODY = json.dumps({"rooms": [
    {"room": "lobby", "topic": "the hub", "last_seq": 12},
    {"room": "mb-alice", "topic": None, "last_seq": 3},
    {"room": "d-jobs", "topic": "work", "last_seq": 7},
    {"room": "BAD NAME", "topic": "x", "last_seq": 1},
    "not-a-dict",
]})

DID_A = D.did_from_priv(D.generate()[0])
ROOM_BODY = json.dumps({"room": "lobby", "last_seq": 99, "messages": [
    {"seq": 98, "ts": "t", "from": DID_A, "text": "signed hello", "nonce": 5},
    {"seq": 99, "ts": "t", "from": "~newcomer", "text": "anon hello", "nonce": None},
    "junk",
]})


posted = {}
_extra_msgs = []


def fake_get(url, timeout):
    if url.endswith("/rooms?format=json"):
        return 200, ROOMS_BODY
    if "/say-signed/" in url:
        posted["url"] = url
        if "/r/refuse/" in url:
            return 403, "signed writes only"
        _extra_msgs.append({"seq": 100, "ts": "t", "from": DID_A, "text": "hello", "nonce": 7})
        return 200, "posted seq 100"
    if "/r/lobby" in url:
        body = json.loads(ROOM_BODY)
        body["messages"] = list(body["messages"]) + _extra_msgs
        return 200, json.dumps(body)
    if "/r/down" in url:
        return 503, "unavailable"
    if "/r/garbage" in url:
        return 200, "<<not json at all>>"
    return 404, "no"


def fake_post(url, obj, timeout):
    return 200, "posted seq 100"


pc = PC.ProtocolClient(base="https://example.test", http_get=fake_get, http_post=fake_post)

rooms = pc.list_rooms()
check("list_rooms keeps only grammar-valid rooms", [r["room"] for r in rooms] == ["lobby", "mb-alice", "d-jobs"])
check("list_rooms classifies a mailbox room", next(r for r in rooms if r["room"] == "mb-alice")["kind"] == "mailbox")
check("list_rooms classifies an ownable room", next(r for r in rooms if r["room"] == "d-jobs")["kind"] == "ownable")
check("list_rooms carries the topic", next(r for r in rooms if r["room"] == "lobby")["topic"] == "the hub")

view = pc.read_room("lobby")
check("read_room returns the messages and the tail", len(view["messages"]) == 2 and view["last_seq"] == 99)
check("a did:key writer is marked verified", view["messages"][0]["verified"] is True)
check("a ~nick writer is NOT verified", view["messages"][1]["verified"] is False)
check("message text is passed through untouched", view["messages"][0]["text"] == "signed hello")

raised = False
try:
    pc.read_room("BAD NAME")
except PC.ProtocolError:
    raised = True
check("read_room rejects an invalid room name", raised)

msg = ""
try:
    pc.read_room("down")
except PC.ProtocolError as e:
    msg = str(e)
check("read_room raises on a non-200", bool(msg))
check("read_room surfaces the server's own words on a non-200", "unavailable" in msg)

raised = False
try:
    pc.read_room("garbage")
except PC.ProtocolError:
    raised = True
check("read_room raises on a 200 with a non-JSON body (not silent-empty)", raised)

ok, detail = pc.say("lobby", DID_A, "sig", 7, "hello")
check("say posts via the GET say-signed path (NOT a POST technocore would ignore)",
      posted["url"] == P.url_say_signed("lobby", DID_A, "sig", "7", "hello", "https://example.test"))
check("say reports success only after a read-back confirms the message landed", ok is True)
ok2, detail2 = pc.say("refuse", DID_A, "sig", 8, "hello")
check("say surfaces a refusal with the server's own words", ok2 is False and "signed writes only" in detail2)

def _fake_get_noecho(url, timeout):
    if "/say-signed/" in url:
        return 200, "accepted"
    if "/r/lobby" in url:
        return 200, json.dumps({"room": "lobby", "last_seq": 1, "messages": []})
    return 404, "no"
pc_noecho = PC.ProtocolClient(base="https://example.test", http_get=_fake_get_noecho)
ok3, detail3 = pc_noecho.say("lobby", DID_A, "sig", 9, "vanished")
check("say reports NOT confirmed when the post never appears in the room", ok3 is False and "not confirm" in detail3)

from urllib.parse import unquote as _unq  # noqa: E402
_store = {}
def _fake_kv(url, timeout):
    if "/set/" in url:
        nskey, val = url.split("/kv/", 1)[1].split("/set/", 1)
        _store[nskey] = _unq(val)
        return 200, "ok"
    if "/kv/" in url:
        v = _store.get(url.split("/kv/", 1)[1])
        return (200, "!! UNTRUSTED CONTENT\n\n" + v) if v is not None else (404, "no note")
    return 404, "no"
_nap = lambda _s: None
pc_kv = PC.ProtocolClient(base="https://example.test", http_get=_fake_kv, sleep=_nap)
okw, _dw = pc_kv.set_note("did-77", "slot", "VALUE-123", confirm=True)
check("set_note confirm=True is ok when the read-back matches the write", okw is True)
check("get_note reads the value back, banner stripped", pc_kv.get_note("did-77", "slot") == "VALUE-123")

def _fake_kv_stale(url, timeout):
    if "/set/" in url:
        return 200, "ok"
    if "/kv/" in url:
        return 200, "!! UNTRUSTED CONTENT\n\nOLD-VALUE"
    return 404, "no"
pc_stale = PC.ProtocolClient(base="https://example.test", http_get=_fake_kv_stale, sleep=_nap)
oks, dets = pc_stale.set_note("did-77", "slot", "NEW-VALUE", confirm=True)
check("set_note confirm=True is NOT ok when the slot still shows a different value (the grant-never-landed bug)",
      oks is False and "read-back" in dets)

_lag = {"reads": 0}
def _fake_kv_laggy(url, timeout):
    if "/set/" in url:
        return 200, "ok"
    if "/kv/" in url:
        _lag["reads"] += 1
        val = "LAGGY-VALUE" if _lag["reads"] >= 2 else "OLD-VALUE"
        return 200, "!! UNTRUSTED CONTENT\n\n" + val
    return 404, "no"
pc_laggy = PC.ProtocolClient(base="https://example.test", http_get=_fake_kv_laggy, sleep=_nap)
okl, _dl = pc_laggy.set_note("did-77", "slot", "LAGGY-VALUE", confirm=True)
check("set_note confirm=True RECOVERS a lagged write on a later read-back (no false-negative)",
      okl is True and _lag["reads"] >= 2)

_wr = {"writes": 0}
def _fake_kv_flaky_write(url, timeout):
    if "/set/" in url:
        _wr["writes"] += 1
        return (200, "ok") if _wr["writes"] >= 2 else (503, "busy")
    if "/kv/" in url:
        return 200, "!! UNTRUSTED CONTENT\n\nWRITE-VALUE"
    return 404, "no"
pc_fw = PC.ProtocolClient(base="https://example.test", http_get=_fake_kv_flaky_write, sleep=_nap)
okfw, _dfw = pc_fw.set_note("did-77", "slot", "WRITE-VALUE", confirm=True)
check("set_note retries a transient write failure and then confirms", okfw is True and _wr["writes"] >= 2)


class RecordingClient:
    """Stands in for the network: records the last say() and never touches a socket."""
    def __init__(self):
        self.said = None
    def list_rooms(self):
        return [{"room": "lobby", "topic": None, "last_seq": 1, "kind": "open"}]
    def read_room(self, room, since=None, limit=50):
        return {"room": room, "messages": [], "last_seq": None, "kind": "open"}
    def say(self, room, did, sig, nonce, swept_text):
        self.said = {"room": room, "did": did, "sig": sig, "nonce": nonce, "text": swept_text}
        return True, "ok"


PW = "correct horse battery staple"
state = Path(tempfile.mkdtemp(prefix="sliceb_"))
rc = RecordingClient()
dash = SRV.Dashboard(str(state), protocol_client=rc)
dash.ks.generate(PW)
owner_did = dash.ks.public_did()

raw = "  hello\nthere  "
code, out = dash.say({"room": "lobby", "text": raw, "passphrase": PW})
check("say returns ok", code == 200 and out.get("ok"))
swept = P.single_line(raw)
check("the stored/returned text is the SWEPT text", out["text"] == swept == "hello there")
check("the client was handed the swept text, not the raw", rc.said["text"] == swept)
check("the signature is by the OWNER key over <room>|<nonce>|<swept>",
      D.verify_by_did(owner_did, rc.said["sig"], P.message_sig_input("lobby", int(rc.said["nonce"]), swept)))
check("the from is the owner did", rc.said["did"] == owner_did)

n1 = int(rc.said["nonce"])
dash.say({"room": "lobby", "text": "again", "passphrase": PW})
check("the second post's nonce is strictly greater", int(rc.said["nonce"]) > n1)

rc.said = None
code, out = dash.say({"room": "lobby", "text": "secret", "passphrase": "wrong wrong wrong"})
check("a wrong passphrase is 403", code == 403)
check("a wrong passphrase posts nothing", rc.said is None)

check("a bad room name is 400", dash.say({"room": "BAD NAME", "text": "x", "passphrase": PW})[0] == 400)
check("an all-whitespace message is 400", dash.say({"room": "lobby", "text": "   \n  ", "passphrase": PW})[0] == 400)
check("an over-long message is 400", dash.say({"room": "lobby", "text": "x" * 4097, "passphrase": PW})[0] == 400)

check("read_room delegates and validates", dash.read_room("lobby")[0] == 200)
check("read_room rejects a bad name at the server too", dash.read_room("BAD NAME")[0] == 400)
check("list_rooms delegates", dash.list_rooms()[0] == 200)

RLO = chr(0x202e)
ZWSP = chr(0x200b)
check("single_line drops a bidi override", P.single_line("a" + RLO + "b") == "a b")
check("single_line drops DEL and a C1 control", P.single_line("a\x7fb\x9fc") == "a b c")
check("single_line drops a zero-width space", P.single_line("a" + ZWSP + "b") == "a b")
check("single_line leaves ordinary text untouched", P.single_line("hello world") == "hello world")
rc.said = None
dash.say({"room": "lobby", "text": "safe" + RLO + "text", "passphrase": PW})
check("a message with a bidi char signs over its swept form",
      D.verify_by_did(owner_did, rc.said["sig"],
                      P.message_sig_input("lobby", int(rc.said["nonce"]), rc.said["text"]))
      and RLO not in rc.said["text"])


class Clk:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t


clk = Clk()
state2 = Path(tempfile.mkdtemp(prefix="slicebU_"))
rc2 = RecordingClient()
dash2 = SRV.Dashboard(str(state2), protocol_client=rc2, clock=clk)
dash2.ks.generate(PW)
udid = dash2.ks.public_did()

check("chat starts LOCKED", dash2.chat_status()[1]["unlocked"] is False)
check("posting with no passphrase while locked is 403 need-unlock",
      dash2.say({"room": "lobby", "text": "hi"})[0] == 403)

check("unlock with a wrong passphrase is 403", dash2.unlock_chat({"passphrase": "nope nope nope one", "seconds": 300})[0] == 403)
check("unlock still locked after a wrong passphrase", dash2.chat_status()[1]["unlocked"] is False)
check("unlock with a silly duration is 400", dash2.unlock_chat({"passphrase": PW, "seconds": 5})[0] == 400)
check("unlock over the 8h cap is 400", dash2.unlock_chat({"passphrase": PW, "seconds": 999999})[0] == 400)

code, out = dash2.unlock_chat({"passphrase": PW, "seconds": 300})
check("a valid unlock returns ok + an until", code == 200 and out["ok"] and out["until"] == 1300)
check("chat_status now reports unlocked", dash2.chat_status()[1]["unlocked"] is True)

rc2.said = None
code, out = dash2.say({"room": "lobby", "text": "posted on the unlock"})
check("posting with NO passphrase now works (held key)", code == 200 and out["ok"])
check("the held-key post is signed by the owner key",
      D.verify_by_did(udid, rc2.said["sig"], P.message_sig_input("lobby", int(rc2.said["nonce"]), rc2.said["text"])))

clk.t = 1301.0
check("chat_status reports locked after expiry", dash2.chat_status()[1]["unlocked"] is False)
check("posting with no passphrase after expiry is 403 again", dash2.say({"room": "lobby", "text": "late"})[0] == 403)

dash2.unlock_chat({"passphrase": PW, "seconds": 300})
check("re-unlocked", dash2.chat_status()[1]["unlocked"] is True)
dash2.lock_chat()
check("lock_chat wipes the window immediately", dash2.chat_status()[1]["unlocked"] is False)
check("a one-shot passphrase still posts even while chat is locked",
      dash2.say({"room": "lobby", "text": "strict path", "passphrase": PW})[0] == 200)

_collide = P.message_sig_input("room-owners", 123, "5|did:key:zAtk") == P.note_sig_input("room-owners", "123", "5", "did:key:zAtk")
check("the message/note signing strings DO collide byte-for-byte (the flaw is real)", _collide)
dash2.unlock_chat({"passphrase": PW, "seconds": 300})
for ns in ("room-owners", "room-allow", "room-nonce"):
    rc2.said = None
    code, _ = dash2.say({"room": ns, "text": "5|did:key:zAtk"})
    check("held-key say to reserved namespace %r is refused" % ns, code == 400 and rc2.said is None)
    code2, _ = dash2.say({"room": ns, "text": "5|x", "passphrase": PW})
    check("one-shot say to reserved namespace %r is refused" % ns, code2 == 400)
dash2.lock_chat()
check("a normal room with a pipe in the text still posts",
      dash2.say({"room": "lobby", "text": "a | b | c", "passphrase": PW})[0] == 200)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
