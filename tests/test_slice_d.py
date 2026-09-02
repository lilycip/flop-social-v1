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
stored = dash._load_grant_record()[0]
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
      dash._load_grant_record()[0].get("grant_id") == _o.get("grant_id"))
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
stored = dash._load_grant_record()[0]

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
dash._store_grant(stored, True, False)
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

# --- Kill-switch + resend honesty under a failed publish ---
st4 = Path(tempfile.mkdtemp())
d4 = SRV.Dashboard(str(st4), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d4.ks.generate(PW)
d4.link_agent({"agent_did": AGENT_DID, "nick": "a"})

# A stop whose publish fails must persist as a RETRYABLE stop, never read as "stopped".
d4.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
d4.pc.fail = True
_sc, _so = d4.revoke_grant({"passphrase": PW})
check("a failed stop reports published:False + stopped:False", _so["published"] is False and _so["stopped"] is False)
_gs = d4.grant_status()[1]
check("a failed stop is flagged stop_unsent (warn loud, keep the resend)", _gs.get("stop_unsent") is True)
check("a failed stop is NOT active and NOT a permissive 'unsent' grant",
      _gs.get("active") is False and _gs.get("unsent") is False and _gs.get("is_stop") is True)

# An undelivered stop must NOT be destroyable by Unlink/relink - both would strand a running agent.
check("Unlink is REFUSED while a stop is undelivered (never discard a pending stop)",
      d4.unlink_agent()[0] == 409)
_, _OTHER4 = D.generate()
check("switching to a DIFFERENT agent is REFUSED while a stop is undelivered",
      d4.link_agent({"agent_did": _OTHER4, "nick": "b"})[0] == 409)
check("re-linking the SAME agent is still allowed (the recovery path)",
      d4.link_agent({"agent_did": AGENT_DID, "nick": "a"})[0] == 200)

# Resend after a stop must re-transport the STOP, never resurrect the prior permissive grant.
_rc, _ro = d4.resend_grant()
check("resend after a stop re-sends the STOP (is_stop), still honest published:False while down",
      _ro.get("is_stop") is True and _ro.get("published") is False and _ro.get("ok") is True)
_stop_val = json.loads(d4.pc.notes[-1][2])
check("the resent bytes are the empty-allow stop, not a permissive grant", _stop_val.get("allow") == {})
d4.pc.fail = False
_rc2, _ro2 = d4.resend_grant()
check("resend of the stop lands once the network recovers", _ro2.get("published") is True and _ro2.get("is_stop") is True)
check("after the stop lands, no active grant and no lingering stop_unsent",
      d4.grant_status()[1].get("active") is False and d4.grant_status()[1].get("stop_unsent") is False)

# Resend must refuse a grant that is no longer valid (revoked), never put it back on the wire.
d5dir = Path(tempfile.mkdtemp())
d5 = SRV.Dashboard(str(d5dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d5.ks.generate(PW)
d5.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d5.pc.fail = True
d5.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_revoked_gid = d5.grant_status()[1]["grant_id"]
d5._add_revoked(_revoked_gid)  # simulate the grant having been revoked out from under a stale resend
_notes_before_bad_resend = len(d5.pc.notes)
_bc, _bo = d5.resend_grant()
check("resend REFUSES a revoked grant (never re-transports lost authority)",
      _bo.get("ok") is False and _bo.get("published") is False)
check("the refused resend wrote nothing to the wire", len(d5.pc.notes) == _notes_before_bad_resend)

# An unreadable grant.json must FAIL CLOSED (like the revoked set), never launder to "no grant":
# a truncated/locked file may hold a live grant or a pending stop.
d6dir = Path(tempfile.mkdtemp())
d6 = SRV.Dashboard(str(d6dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d6.ks.generate(PW)
d6.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d6.grant_path.write_text("{ this is not valid json", "utf-8")
_g6 = d6.grant_status()[1]
check("an unreadable grant record reports unknown:True + active:False (fail closed, not 'no grant')",
      _g6.get("unknown") is True and _g6.get("active") is False)
check("Unlink is REFUSED while the grant record is unreadable", d6.unlink_agent()[0] == 409)
check("resend REFUSES an unreadable grant record", d6.resend_grant()[1].get("ok") is False)

# agent.json - the THIRD input - must ALSO fail closed. A live grant + an unreadable
# agent.json must not let revoke blank the grant or a relink orphan it.
d7dir = Path(tempfile.mkdtemp())
d7 = SRV.Dashboard(str(d7dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d7.ks.generate(PW)
d7.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d7.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
d7.agent_path.write_text("{ truncated agent file", "utf-8")
_g7 = d7.grant_status()[1]
check("a live grant with an UNREADABLE agent.json reports unknown:True (never 'no grant')",
      _g7.get("unknown") is True and _g7.get("active") is False)
_rv7 = d7.revoke_grant({"passphrase": PW})
check("revoke REFUSES to blank the grant when agent.json is unreadable (never strand a running agent)",
      _rv7[1].get("ok") is False and _rv7[1].get("need") == "relink")
check("the grant record still exists after the refused revoke (not blanked)",
      d7._load_grant_record()[0] is not None)
# Recovery: re-linking the correct did restores a readable state WITHOUT clearing the grant.
_lk7 = d7.link_agent({"agent_did": AGENT_DID, "nick": "a"})
check("re-linking the same did after an unreadable agent.json succeeds (recovery path)", _lk7[0] == 200)
check("the grant is preserved + addressable again after the relink (active)",
      d7.grant_status()[1].get("active") is True)

# A grant bound to a DIFFERENT agent than the one linked reads as unknown (may be live for that other agent).
d8dir = Path(tempfile.mkdtemp())
d8 = SRV.Dashboard(str(d8dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d8.ks.generate(PW)
d8.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d8.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_, _OTHER8 = D.generate()
d8._write_json(d8.agent_path, {"agent_did": _OTHER8, "nick": "b"})  # agent record now names a DIFFERENT did
check("a grant bound to a different agent than the linked one reports unknown:True (not 'no grant')",
      d8.grant_status()[1].get("unknown") is True)

# A tampered record (is_stop flag true but a NON-empty allow) reads as unknown, not a benign stop.
d9dir = Path(tempfile.mkdtemp())
d9 = SRV.Dashboard(str(d9dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d9.ks.generate(PW)
d9.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d9.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_g9grant = d9._load_grant_record()[0]
d9._store_grant(_g9grant, True, True)  # mislabel a permissive grant as a stop
check("a record whose is_stop disagrees with a non-empty allow reads as unknown (tamper guard)",
      d9.grant_status()[1].get("unknown") is True)

# Wall 1: agent.json UNREADABLE + a live grant for X. grant.json IS readable and names X, so a recovery
# relink to a WRONG did (a paste error) must be REFUSED - otherwise the next Stop binds to the wrong agent
# and falsely reports X stopped while X's permissive grant is still replayable on the slot.
d10dir = Path(tempfile.mkdtemp())
d10 = SRV.Dashboard(str(d10dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d10.ks.generate(PW)
d10.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d10.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
d10.agent_path.write_text("{ truncated agent file", "utf-8")
_, _Y10 = D.generate()
_bad10 = d10.link_agent({"agent_did": _Y10, "nick": "y"})
check("recovery relink to a did that does NOT own the live grant is REFUSED (Wall 1, unreadable agent.json)",
      _bad10[0] == 409 and _bad10[1].get("need") == "relink-stored" and _bad10[1].get("stored_agent_did") == AGENT_DID)
check("the wrong-did recovery relink did not overwrite agent.json (still guided to the right did)",
      d10.grant_status()[1].get("unknown") is True)
_ok10 = d10.link_agent({"agent_did": AGENT_DID, "nick": "a"})
check("recovery relink to the grant's REAL owner succeeds and preserves the grant (active)",
      _ok10[0] == 200 and d10.grant_status()[1].get("active") is True)

# Wall 2: agent.json rewritten to a DIFFERENT valid did Y while a live grant for X is
# stored. A Stop is bound to the LINKED agent, so a stop for Y would NOT cover X - revoke must REFUSE and
# report stopped:False, never sign a wrong-agent stop and claim the agent is stopped.
d11dir = Path(tempfile.mkdtemp())
d11 = SRV.Dashboard(str(d11dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d11.ks.generate(PW)
d11.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d11.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_, _Y11 = D.generate()
d11._write_json(d11.agent_path, {"agent_did": _Y11, "nick": "b"})
_notes_before11 = len(d11.pc.notes)
_rv11 = d11.revoke_grant({"passphrase": PW})
check("STOP REFUSES when the stored grant is bound to a different agent than linked (never false 'stopped')",
      _rv11[1].get("stopped") is False and _rv11[1].get("ok") is False and _rv11[1].get("need") == "relink-stored")
check("the refusal names the agent the live grant is actually bound to", _rv11[1].get("stored_agent_did") == AGENT_DID)
check("the wrong-agent STOP was never published to the wire", len(d11.pc.notes) == _notes_before11)
check("the live grant for X was NOT superseded by a wrong-agent stop",
      d11._load_grant_record()[0].get("agent_did") == AGENT_DID)
# Recovery must NOT deadlock: re-linking the grant's true owner (a switch back to X) re-associates rather
# than destroying the grant, and the Stop then lands for the right agent.
_re11 = d11.link_agent({"agent_did": AGENT_DID, "nick": "a"})
check("re-linking the grant's owner after a mismatch RE-ASSOCIATES (preserves the grant, active again)",
      _re11[0] == 200 and d11.grant_status()[1].get("active") is True)
_rv11b = d11.revoke_grant({"passphrase": PW})
check("Stop now lands for the correct agent after re-association (stopped:True, bound to X)",
      _rv11b[1].get("stopped") is True and json.loads(d11.pc.notes[-1][2]).get("allow") == {})
# And a GENUINE switch to a third agent that does not own the grant is still blocked until the stop lands.
d11b_dir = Path(tempfile.mkdtemp())
d11b = SRV.Dashboard(str(d11b_dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d11b.ks.generate(PW)
d11b.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d11b.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_, _Z11 = D.generate()
_sw11 = d11b.link_agent({"agent_did": _Z11, "nick": "z"})
check("a genuine switch to an agent that does NOT own a LIVE grant is still blocked (stop first)",
      _sw11[0] == 409 and _sw11[1].get("need") == "stop")

# Write order: a superseding sign whose FIRST store-write fails (disk full / AV lock)
# must leave the OLD grant readable and correctly ACTIVE - never inactive-because-its-id-was-revoked-before-
# the-replacement-landed (which would launder a still-live grant into a safe-looking state and permit unlink).
d12dir = Path(tempfile.mkdtemp())
d12 = SRV.Dashboard(str(d12dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d12.ks.generate(PW)
d12.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d12.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_old_gid12 = d12.grant_status()[1]["grant_id"]
_orig_store12 = d12._store_grant
_st12 = {"n": 0}
def _boom12(grant, published, is_stop):
    _st12["n"] += 1
    if _st12["n"] == 1:
        raise OSError("simulated disk-full on the superseding write")
    return _orig_store12(grant, published, is_stop)
d12._store_grant = _boom12
_raised12 = False
try:
    d12.sign_grant({"allow": {"CLAIM": 9}, "duration_seconds": 604800, "passphrase": PW})
except OSError:
    _raised12 = True
d12._store_grant = _orig_store12
check("a superseding sign whose first write fails surfaces the error (a 500, not a silent success)", _raised12)
_g12 = d12.grant_status()[1]
check("after the failed superseding write, the OLD grant is still ACTIVE, never false-inactive",
      _g12.get("active") is True and _g12.get("grant_id") == _old_gid12)
check("the still-live old grant BLOCKS unlink (not laundered into a safe state)", d12.unlink_agent()[0] == 409)

# A present agent.json whose did is the WRONG TYPE (a list) is corrupt, not "no agent":
# it must fail closed (unknown) and route into the guarded recovery, where Wall 1 again refuses a wrong did.
d13dir = Path(tempfile.mkdtemp())
d13 = SRV.Dashboard(str(d13dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d13.ks.generate(PW)
d13.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d13.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
d13._write_json(d13.agent_path, {"agent_did": [AGENT_DID], "nick": "x"})
check("a wrong-TYPE agent did (a list) reads as unknown:True (fail closed, F3)",
      d13.grant_status()[1].get("unknown") is True)
check("revoke refuses on a wrong-type agent did (routes to relink recovery, never a blank)",
      d13.revoke_grant({"passphrase": PW})[1].get("need") == "relink")
_, _WRONG13 = D.generate()
_bad13 = d13.link_agent({"agent_did": _WRONG13, "nick": "y"})
check("relink to a did that does NOT own the stored grant is refused (Wall 1 over a wrong-type record)",
      _bad13[0] == 409 and _bad13[1].get("need") == "relink-stored" and _bad13[1].get("stored_agent_did") == AGENT_DID)
_ok13 = d13.link_agent({"agent_did": AGENT_DID, "nick": "a"})
check("relink to the grant's real owner recovers (200) and the grant is active again",
      _ok13[0] == 200 and d13.grant_status()[1].get("active") is True)

# A grant record with a grant_id but an ABSENT inner agent_did (hand-corrupted but valid JSON) must fail
# CLOSED everywhere: a predicate like `isinstance(x,str) and x!=y` reads a MISSING did as "no conflict"
# and falls open, reproducing the false-"stopped" this suite exists to prevent.
d14dir = Path(tempfile.mkdtemp())
d14 = SRV.Dashboard(str(d14dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d14.ks.generate(PW)
d14.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d14.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
_rec14 = json.loads(d14.grant_path.read_text("utf-8"))
del _rec14["grant"]["agent_did"]  # strip the inner did, keep grant_id + valid JSON
d14.grant_path.write_text(json.dumps(_rec14), "utf-8")
check("a grant with grant_id but NO inner agent_did reads unknown:True (fail closed, not benign)",
      d14.grant_status()[1].get("unknown") is True)
_notes14 = len(d14.pc.notes)
_rv14 = d14.revoke_grant({"passphrase": PW})
check("revoke REFUSES a corrupt-owner grant (need manual, never a false 'stopped')",
      _rv14[1].get("stopped") is False and _rv14[1].get("ok") is False and _rv14[1].get("need") == "manual")
check("the corrupt-owner revoke published NOTHING to the wire", len(d14.pc.notes) == _notes14)
check("unlink is REFUSED while the grant owner is unprovable", d14.unlink_agent()[0] == 409)
d14.agent_path.write_text("{ truncated agent file", "utf-8")
_, _Y14 = D.generate()
_lk14 = d14.link_agent({"agent_did": _Y14, "nick": "y"})
check("recovery relink is REFUSED (need manual) when the stored grant's owner is corrupt (Wall 1)",
      _lk14[0] == 409 and _lk14[1].get("need") == "manual")

# A present agent.json with a FALSY did ("") must fail closed (route to guarded recovery),
# never read as "no agent linked" and skip Wall 1 while a grant for X is stored.
d15dir = Path(tempfile.mkdtemp())
d15 = SRV.Dashboard(str(d15dir), clock=Clock(1_700_000_000), protocol_client=FakePC(), kibble_client=FeedKibble(AGENT_DID))
d15.ks.generate(PW)
d15.link_agent({"agent_did": AGENT_DID, "nick": "a"})
d15.sign_grant({"allow": {"CLAIM": 5}, "duration_seconds": 604800, "passphrase": PW})
d15._write_json(d15.agent_path, {"agent_did": "", "nick": "x"})
check("an empty-string agent did reads unknown:True (fail closed, F2)",
      d15.grant_status()[1].get("unknown") is True)
_, _WRONG15 = D.generate()
_bad15 = d15.link_agent({"agent_did": _WRONG15, "nick": "y"})
check("relink to a non-owner is refused even when agent.json had a falsy did (Wall 1 not skipped, F2)",
      _bad15[0] == 409 and _bad15[1].get("need") == "relink-stored" and _bad15[1].get("stored_agent_did") == AGENT_DID)
_ok15 = d15.link_agent({"agent_did": AGENT_DID, "nick": "a"})
check("relink to the grant's owner recovers after a falsy-did agent file",
      _ok15[0] == 200 and d15.grant_status()[1].get("active") is True)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
