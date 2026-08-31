"""Oracle for Slice D: My Agent (dashboard/server.py). Proves: linking stores only the agent's
PUBLIC did and refuses a bad did or the owner's own did; a signed grant verifies against the owner
key with shared.grant, a 0 ceiling collapses to gated, unknown/negative/bad-duration are refused,
a wrong passphrase signs nothing, and the CHAT unlock cannot sign a grant (invariant 6 not widened);
grant_status reports a stored grant as inactive once expired or revoked; a STOP (revoke) needs the
passphrase, signs+publishes an empty-allow grant to the owner slot, and clears local state; the feed
filters the board to the agent DID; reject consumes a pending action so it never signs. Temp dir; ASCII.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as D  # noqa: E402
from shared import grant as G  # noqa: E402
from shared import names as N  # noqa: E402
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


class FeedKibble:
    """A KibbleClient stand-in whose board carries jobs for a chosen agent DID."""
    def __init__(self, agent_did):
        self.agent_did = agent_did

    def read_board(self):
        return {"jobs": [
            {"job_id": "kposted0001", "category": "research", "title": "agent posted this",
             "status": "open", "poster_did": self.agent_did, "worker_did": "", "useful_n": 0, "not_n": 0},
            {"job_id": "kworked0002", "category": "build", "title": "agent working this",
             "status": "claimed", "poster_did": "did:key:zSomeoneElse", "worker_did": self.agent_did,
             "useful_n": 1, "not_n": 0},
            {"job_id": "kother00003", "category": "explain", "title": "nothing to do with us",
             "status": "open", "poster_did": "did:key:zStranger", "worker_did": "", "useful_n": 0, "not_n": 0},
        ], "stats": {}}


class FakePC:
    """A ProtocolClient stand-in that RECORDS set_note calls (so grant publishing is tested with no
    network) and can be told to fail, to prove a publish failure never undoes the local sign."""
    def __init__(self):
        self.notes = []
        self.fail = False

    def set_note(self, namespace, key, value, confirm=False):
        self.notes.append((namespace, key, value))
        if self.fail:
            raise RuntimeError("network down")
        return True, "ok " + namespace + "/" + key


PW = "correct horse battery staple"
AGENT_PRIV, AGENT_DID = D.generate()

clk = Clock(1_700_000_000)
state = Path(tempfile.mkdtemp())
fake_pc = FakePC()
dash = SRV.Dashboard(str(state), clock=clk, protocol_client=fake_pc, kibble_client=FeedKibble(AGENT_DID))
dash.ks.generate(PW)
owner_did = dash.ks.public_did()
owner_pub = D.pub_raw_from_did(owner_did)

check("signing a grant with no agent linked is refused 400", dash.sign_grant(
    {"allow": {"CLAIM": 5}, "duration_seconds": 86400, "passphrase": PW})[0] == 400)

check("no agent linked at first", dash.agent_status()[1]["linked"] is False)
check("a bad did:key is refused", dash.link_agent({"agent_did": "not-a-did"})[0] == 400)
check("the owner's own did is refused as the agent", dash.link_agent({"agent_did": owner_did})[0] == 400)
code, out = dash.link_agent({"agent_did": AGENT_DID, "nick": "jarvis"})
check("a valid agent did links", code == 200 and out["ok"])
st = dash.agent_status()[1]
check("agent_status reports the linked did + nick", st["linked"] and st["agent_did"] == AGENT_DID and st["nick"] == "jarvis")

knobs = dash.grant_catalog()
kmap = {k["klass"]: k for k in knobs}
check("catalog carries the everyday classes", "CLAIM" in kmap and "ATTEST:not" in kmap)
check("catalog flags the dangerous classes from the primitive",
      kmap["NOTE_WRITE:identity"]["dangerous"] is True and kmap["NOTE_WRITE:ownership"]["dangerous"] is True
      and kmap["ATTEST:useful:no-board-match"]["dangerous"] is True)
check("catalog does NOT flag ordinary classes",
      kmap["CLAIM"]["dangerous"] is False and kmap["ATTEST:not"]["dangerous"] is False
      and kmap["SAY"]["dangerous"] is False)

check("an unknown permission is refused", dash.sign_grant(
    {"allow": {"bogus:everything": 5}, "duration_seconds": 86400, "passphrase": PW})[0] == 400)
check("a negative ceiling is refused", dash.sign_grant(
    {"allow": {"CLAIM": -1}, "duration_seconds": 86400, "passphrase": PW})[0] == 400)
check("a too-short duration is refused", dash.sign_grant(
    {"allow": {"CLAIM": 5}, "duration_seconds": 60, "passphrase": PW})[0] == 400)
check("a too-long duration is refused", dash.sign_grant(
    {"allow": {"CLAIM": 5}, "duration_seconds": 99_999_999, "passphrase": PW})[0] == 400)
check("a float ceiling is refused", dash.sign_grant(
    {"allow": {"CLAIM": 5.9}, "duration_seconds": 86400, "passphrase": PW})[0] == 400)
check("an absurdly high ceiling is refused", dash.sign_grant(
    {"allow": {"CLAIM": 10**9}, "duration_seconds": 86400, "passphrase": PW})[0] == 400)
check("a wrong passphrase signs no grant", dash.sign_grant(
    {"allow": {"CLAIM": 5}, "duration_seconds": 86400, "passphrase": "nope nope nope one"})[0] == 403)
check("no grant is stored after the failures", dash.grant_status()[1]["active"] is False)

code, out = dash.sign_grant({"allow": {"CLAIM": 10, "RESULT": 10, "ATTEST:not": 200, "SAY": 0},
                             "duration_seconds": 7 * 86400, "passphrase": PW})
check("a valid grant signs", code == 200 and out["ok"])
stored = dash._read_json(dash.grant_path)
check("the stored grant verifies against the owner key AND is bound to the linked agent",
      G.verify_grant(owner_pub, stored, now=clk(), revoked_ids=set(), expected_agent=AGENT_DID))
check("the stored grant carries the agent did", stored.get("agent_did") == AGENT_DID)
check("the grant does NOT verify for a different agent",
      not G.verify_grant(owner_pub, stored, now=clk(), revoked_ids=set(), expected_agent=D.generate()[1]))
check("a 0 ceiling collapsed to gated (SAY absent from allow)", "SAY" not in stored["allow"])
check("the granted classes are present with their ceilings",
      stored["allow"].get("CLAIM") == 10 and stored["allow"].get("ATTEST:not") == 200)
check("a non-empty grant carries a MODEL thinking budget",
      stored["allow"].get("MODEL") == SRV.DEFAULT_MODEL_CEILING)

check("signing published the grant to the protocol", out.get("published") is True)
check("exactly one note was written", len(fake_pc.notes) == 1)
_ns, _key, _val = fake_pc.notes[-1]
_exp_ns = D.did_note_ns(owner_did)
_exp_key = D.note_shard_key(owner_did)[1] + "-grant"
check("published to the owner did-note namespace", _ns == _exp_ns)
check("published to the fixed grant key (distinct from the identity note)", _key == _exp_key)
check("the grant key is a valid note key", N.is_valid_name(_key))
_pub = json.loads(_val)
check("the published value is the exact signed grant (compact, single-line JSON)",
      "\n" not in _val and _pub.get("grant_id") == stored.get("grant_id")
      and _pub.get("signature") == stored.get("signature"))
check("the published grant verifies against the owner key",
      G.verify_grant(owner_pub, _pub, now=clk(), revoked_ids=set(), expected_agent=AGENT_DID))

fake_pc.fail = True
_c, _o = dash.sign_grant({"allow": {"CLAIM": 3}, "duration_seconds": 86400, "passphrase": PW})
check("a grant still signs locally when the publish fails", _c == 200 and _o["ok"])
check("the failed publish is reported honestly", _o.get("published") is False)
check("the locally stored grant is the newly signed one despite the publish failure",
      dash._read_json(dash.grant_path).get("grant_id") == _o.get("grant_id"))
check("grant_status flags an undelivered grant as unsent (offer a resend)",
      dash.grant_status()[1].get("unsent") is True)
_rc, _ro = dash.resend_grant()
check("resend still reports published:False while the network is down (honest, no false success)",
      _rc == 200 and _ro["published"] is False and _ro["grant_id"] == _o["grant_id"])
fake_pc.fail = False
_rc2, _ro2 = dash.resend_grant()
check("resend re-publishes the SAME signed grant and now reports published (no re-sign)",
      _rc2 == 200 and _ro2["published"] is True and _ro2["grant_id"] == _o["grant_id"])
check("after a successful resend the grant is no longer flagged unsent",
      dash.grant_status()[1].get("unsent") is False)
_notes_after_resend = len(fake_pc.notes)
code, out = dash.sign_grant({"allow": {"CLAIM": 10, "RESULT": 10, "ATTEST:not": 200, "SAY": 0},
                             "duration_seconds": 7 * 86400, "passphrase": PW})
check("re-signed the canonical grant for the remaining checks", code == 200 and out["ok"])
stored = dash._read_json(dash.grant_path)

gs = dash.grant_status()[1]
check("grant_status reports active", gs["active"] is True and gs["revoked"] is False)
check("grant_status lists the active allow with danger flags",
      {a["klass"] for a in gs["allow"]} == {"CLAIM", "RESULT", "ATTEST:not"}
      and all(a["dangerous"] is False for a in gs["allow"]))
check("grant_status carries the linked agent", gs["agent"]["agent_did"] == AGENT_DID)

clk.t = 1_700_000_000 + 7 * 86400 + 1
check("an expired grant is reported inactive", dash.grant_status()[1]["active"] is False)
clk.t = 1_700_000_000

dash.unlock_chat({"passphrase": PW, "seconds": 300})
check("chat is unlocked", dash.chat_status()[1]["unlocked"] is True)
check("signing a grant with no passphrase is refused even while chat is unlocked",
      dash.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 86400})[0] == 403)
dash.lock_chat()

check("stopping with no passphrase is refused 403 (a real stop must be signed by the owner key)",
      dash.revoke_grant({})[0] == 403)
_notes_before = len(fake_pc.notes)
code, out = dash.revoke_grant({"passphrase": PW})
check("the stop signs and reports stopped + published", code == 200 and out["stopped"] and out["published"] is True)
check("the stop published one note to the slot", len(fake_pc.notes) == _notes_before + 1)
_sns, _sk, _sval = fake_pc.notes[-1]
_stop = json.loads(_sval)
check("the stop is an EMPTY-allow grant (authorizes nothing on auto)", _stop.get("allow") == {})
check("the stop carries NO MODEL budget (a stop zeroes thinking, not just acting)",
      "MODEL" not in _stop.get("allow", {}))
check("the stop is signed by the owner, bound to the agent, and verifies",
      G.verify_grant(owner_pub, _stop, now=clk(), revoked_ids=set(), expected_agent=AGENT_DID))
check("the stop published to the SAME owner slot",
      _sns == D.did_note_ns(owner_did) and _sk == D.note_shard_key(owner_did)[1] + "-grant")
gs2 = dash.grant_status()[1]
check("after the stop there is no active grant (everything asks you)", gs2["active"] is False)
dash._write_json(dash.grant_path, stored)
check("a restored-but-revoked grant is still inactive",
      dash.grant_status()[1]["active"] is False and dash.grant_status()[1]["revoked"] is True)
fake_pc.fail = True
dash.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 86400, "passphrase": PW})
_fc, _fo = dash.revoke_grant({"passphrase": PW})
check("a stop whose publish FAILS reports stopped:False + published:False (agent may still run) but still clears locally",
      _fc == 200 and _fo["stopped"] is False and _fo["published"] is False and dash.grant_status()[1]["active"] is False)
fake_pc.fail = False

feed = dash.agent_feed()[1]
titles = {i["title"]: i["role"] for i in feed["items"]}
check("the feed shows the jobs the agent posted", titles.get("agent posted this") == "posted")
check("the feed shows the jobs the agent is working", titles.get("agent working this") == "working")
check("the feed excludes jobs that are not the agent's", "nothing to do with us" not in titles)

rid = "req-reject-1"
(dash.pending / (rid + ".json")).write_text(json.dumps(
    {"request_id": rid, "verb": "NOTE_WRITE", "destination": "did-ab",
     "target": {"namespace": "did-ab", "key": "d29", "value": "version:1.4.0"}}), "utf-8")
check("the pending action shows up", any(c["request_id"] == rid for c in dash.pending_cards()["pending"]))
check("reject consumes it", dash.reject({"request_id": rid})[0] == 200)
check("a rejected action no longer shows as pending",
      not any(c["request_id"] == rid for c in dash.pending_cards()["pending"]))
check("rejecting an unknown request is a 404", dash.reject({"request_id": "nope"})[0] == 404)

st2 = Path(tempfile.mkdtemp())
d2 = SRV.Dashboard(str(st2), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d2.ks.generate(PW)
d2.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d2.sign_grant({"allow": {"CLAIM": 1000}, "duration_seconds": 604800, "passphrase": PW})
g1 = d2.grant_status()[1]["grant_id"]
d2.sign_grant({"allow": {"CLAIM": 10}, "duration_seconds": 604800, "passphrase": PW})
g2 = d2.grant_status()[1]["grant_id"]
check("re-signing makes a new grant", g2 != g1)
check("re-signing revoked the prior (looser) grant_id", g1 in d2._read_revoked())

_, OTHER = D.generate()
check("relinking a DIFFERENT agent is refused while a grant is active (stop first)",
      d2.link_agent({"agent_did": OTHER, "nick": "b"})[0] == 409)
check("the active grant is untouched by the refused relink", d2.grant_status()[1]["active"] is True)
d2.revoke_grant({"passphrase": PW})
check("after the stop there is no active grant", d2.grant_status()[1]["active"] is False)
check("re-signing revoked the prior grant_id (the stop superseded it)", g2 in d2._read_revoked())
rc, _ro = d2.link_agent({"agent_did": OTHER, "nick": "b"})
check("after stopping, switching to a different agent succeeds", rc == 200)
check("the switched-to agent inherits NO grant", d2.grant_status()[1]["active"] is False)

d2.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d2.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
check("unlink is refused while a grant is active (stop first)", d2.unlink_agent()[0] == 409)
g3 = d2.grant_status()[1]["grant_id"]
d2.revoke_grant({"passphrase": PW})
check("unlink succeeds after the stop", d2.unlink_agent()[0] == 200)
check("after unlink there is no active grant", d2.grant_status()[1]["active"] is False)
check("the stop revoked the prior grant_id", g3 in d2._read_revoked())

st3 = Path(tempfile.mkdtemp())
d3 = SRV.Dashboard(str(st3), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d3.ks.generate(PW)
d3.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d3.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
check("grant active before corruption", d3.grant_status()[1]["active"] is True)
d3.revoked_path.write_text("{ this is not a list", "utf-8")
check("a corrupt revoked file makes the grant report INACTIVE (fail closed)",
      d3.grant_status()[1]["active"] is False)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
