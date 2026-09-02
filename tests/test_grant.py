"""Oracle for shared/grant.py, the standing permission slip. Proves: it is signed and
verified fail-closed; it is an ALLOWLIST so absence means gated (safe by default); the
dangerous classes are off unless the user adds them; a user CAN add any class; ceilings are
per-class; expiry and revocation both drop to gating. ASCII only, no network.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import did, grant  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


owner_priv, owner_did = did.generate()
owner_pub = did.pub_raw(owner_priv)
other_priv, _ = did.generate()
_, AGENT_DID = did.generate()

check("not-useful ATTEST is its own class",
      grant.grant_class("ATTEST", {"job_id": "j"}, {"useful": False}) == "ATTEST:not")
check("useful ATTEST with a board match is auto-eligible class",
      grant.grant_class("ATTEST", {"job_id": "j"}, {"useful": True}, board_match=True) == "ATTEST:useful:board-match")
check("useful ATTEST WITHOUT a board match is a DIFFERENT class",
      grant.grant_class("ATTEST", {"job_id": "j"}, {"useful": True}, board_match=False) == "ATTEST:useful:no-board-match")
check("a DID-note write is the identity class (dangerous)",
      grant.grant_class("NOTE_WRITE", {"namespace": "did-94", "key": "k"}) == "NOTE_WRITE:identity")
check("SAY is its own (dangerous) class", grant.grant_class("SAY", {"room": "lobby"}) == "SAY")
check("a LEGACY did-namespace note is still identity",
      grant.grant_class("NOTE_WRITE", {"namespace": "did", "key": "k"}) == "NOTE_WRITE:identity")
check("a room-owners note is the ownership class (dangerous)",
      grant.grant_class("NOTE_WRITE", {"namespace": "room-owners", "key": "d-jobs"}) == "NOTE_WRITE:ownership")
check("a room-allow note is the ownership class (dangerous)",
      grant.grant_class("NOTE_WRITE", {"namespace": "room-allow", "key": "d-jobs"}) == "NOTE_WRITE:ownership")
check("an ordinary note is the plain note class",
      grant.grant_class("NOTE_WRITE", {"namespace": "topic", "key": "lobby"}) == "NOTE_WRITE:note")

ALLOW = {"ATTEST:not": 200, "ATTEST:useful:board-match": 50}
g = grant.build_grant(owner_priv, "g-001", AGENT_DID, issued=1000, expiry=100000, allow=ALLOW)
check("a built grant carries the owner did", g["owner_did"] == owner_did)
check("issued and expiry are stored canonical strings", g["issued"] == "1000" and g["expiry"] == "100000")

now = 5000
revoked = set()
check("a valid grant verifies under the owner key",
      grant.verify_grant(owner_pub, g, now=now, revoked_ids=revoked, expected_agent=AGENT_DID))

# A crafted, non-string grant_id (e.g. a list) must return False, never RAISE out of the "never raises"
# contract (it would otherwise be unhashable in the revoked-set membership test).
_crafted = dict(g)
_crafted["grant_id"] = ["not", "a", "string"]
_nonhash_ok = True
try:
    _r = grant.verify_grant(owner_pub, _crafted, now=now, revoked_ids=revoked, expected_agent=AGENT_DID)
    check("a non-string grant_id verifies False (no raise)", _r is False)
except Exception:
    _nonhash_ok = False
check("verify_grant does NOT raise on a crafted non-hashable grant_id", _nonhash_ok)

def ceil(verb, target=None, verdict=None, board_match=False, gr=g, n=now, rv=None):
    return grant.auto_ceiling(owner_pub, gr, verb, target, verdict, board_match,
                              now=n, revoked_ids=revoked if rv is None else rv, expected_agent=AGENT_DID)


check("a granted class returns its user-set ceiling",
      ceil("ATTEST", {"job_id": "j"}, {"useful": False}) == 200)
check("the useful+board-match class returns its own ceiling",
      ceil("ATTEST", {"job_id": "j"}, {"useful": True}, board_match=True) == 50)
check("SAFE DEFAULT: useful WITHOUT a board match is NOT auto (gated)",
      ceil("ATTEST", {"job_id": "j"}, {"useful": True}, board_match=False) is None)
check("SAFE DEFAULT: a DID-note write (identity) is NOT auto (gated)",
      ceil("NOTE_WRITE", {"namespace": "did-94", "key": "k"}) is None)
check("SAFE DEFAULT: SAY (prose) is NOT auto (gated)", ceil("SAY", {"room": "lobby"}) is None)
check("an unknown verb is NOT auto (gated)", ceil("TRANSFER", {"job_id": "j"}) is None)

g2 = grant.build_grant(owner_priv, "g-002", AGENT_DID, issued=1000, expiry=100000,
                       allow={"NOTE_WRITE:identity": 3})
check("a user who grants the identity class gets its ceiling (their choice)",
      grant.auto_ceiling(owner_pub, g2, "NOTE_WRITE", {"namespace": "did-94", "key": "k"},
                         now=now, revoked_ids=set(), expected_agent=AGENT_DID) == 3)
check("granting one dangerous class does not auto-grant another",
      grant.auto_ceiling(owner_pub, g2, "SAY", {"room": "lobby"}, now=now, revoked_ids=set(), expected_agent=AGENT_DID) is None)

g0 = grant.build_grant(owner_priv, "g-000", AGENT_DID, issued=1000, expiry=100000, allow={})
check("an empty grant authorizes nothing on auto",
      grant.auto_ceiling(owner_pub, g0, "ATTEST", {"job_id": "j"}, {"useful": False},
                         now=now, revoked_ids=set(), expected_agent=AGENT_DID) is None)

check("a grant signed by another key is refused",
      not grant.verify_grant(owner_pub, grant.build_grant(other_priv, "g-x", AGENT_DID, 1000, 100000, ALLOW), now=now, revoked_ids=set(), expected_agent=AGENT_DID))
tampered = dict(g); tampered["allow"] = {"ATTEST:not": 999999}
check("tampering the ceiling breaks the signature", not grant.verify_grant(owner_pub, tampered, now=now, revoked_ids=set(), expected_agent=AGENT_DID))
tampered2 = dict(g); tampered2["expiry"] = "100001"
check("tampering the expiry breaks the signature", not grant.verify_grant(owner_pub, tampered2, now=now, revoked_ids=set(), expected_agent=AGENT_DID))
check("an expired grant is refused", not grant.verify_grant(owner_pub, g, now=200000, revoked_ids=set(), expected_agent=AGENT_DID))
check("a REVOKED grant_id drops to gating", not grant.verify_grant(owner_pub, g, now=now, revoked_ids={"g-001"}, expected_agent=AGENT_DID))
check("revoke means auto_ceiling returns None (gated)",
      grant.auto_ceiling(owner_pub, g, "ATTEST", {"job_id": "j"}, {"useful": False}, now=now, revoked_ids={"g-001"}, expected_agent=AGENT_DID) is None)
check("a missing clock is a reject, not a trust", not grant.verify_grant(owner_pub, g, now=None, revoked_ids=set(), expected_agent=AGENT_DID))
check("a missing revocation set is a reject, not a trust", not grant.verify_grant(owner_pub, g, now=now, revoked_ids=None, expected_agent=AGENT_DID))
check("verify never raises on a non-dict grant", grant.verify_grant(owner_pub, ["x"], now=now, revoked_ids=set(), expected_agent=AGENT_DID) is False)
check("auto_ceiling never raises on garbage",
      grant.auto_ceiling(owner_pub, "notagrant", "ATTEST", {"job_id": "j"}, {"useful": False}, now=now, revoked_ids=set(), expected_agent=AGENT_DID) is None)

raised = False
try:
    grant.build_grant(owner_priv, "g-bad", AGENT_DID, 1000, 100000, {"has a space": 5})
except ValueError:
    raised = True
check("a class name outside the grammar is refused at build", raised)
raised = False
try:
    grant.build_grant(owner_priv, "bad id!", AGENT_DID, 1000, 100000, ALLOW)
except ValueError:
    raised = True
check("a bad grant_id is refused at build", raised)

gz = grant.build_grant(owner_priv, "g-zero", AGENT_DID, 1000, 100000, {"ATTEST:not": 0})
check("a zero-ceiling class is gated (auto_ceiling None, not 0)",
      grant.auto_ceiling(owner_pub, gz, "ATTEST", {"job_id": "j"}, {"useful": False}, now=now, revoked_ids=set(), expected_agent=AGENT_DID) is None)

gw = grant.build_grant(owner_priv, "g-win", AGENT_DID, 1000, 100000, ALLOW, window=3600)
check("window is stored on the grant", gw["window"] == "3600")
check("the default window is a day", g["window"] == "86400")
tw = dict(gw); tw["window"] = "86400"
check("tampering the window breaks the signature", not grant.verify_grant(owner_pub, tw, now=now, revoked_ids=set(), expected_agent=AGENT_DID))
check("a window-bound grant still verifies untouched", grant.verify_grant(owner_pub, gw, now=now, revoked_ids=set(), expected_agent=AGENT_DID))

for k in ("NOTE_WRITE:identity", "NOTE_WRITE:ownership", "ATTEST:useful:no-board-match"):
    check("%s carries a danger flag" % k, grant.is_dangerous(k))
check("room speech (ephemeral) is NOT flagged dangerous", not grant.is_dangerous("SAY"))
check("posting work (RESULT) is NOT flagged dangerous", not grant.is_dangerous("RESULT"))
check("the two auto vote classes are NOT dangerous",
      not grant.is_dangerous("ATTEST:not") and not grant.is_dangerous("ATTEST:useful:board-match"))
check("an unknown/other class is dangerous by default", grant.is_dangerous("OTHER:TRANSFER") and grant.is_dangerous("NOTE_WRITE:unknown"))
gd = grant.build_grant(owner_priv, "g-dang", AGENT_DID, 1000, 100000, {"NOTE_WRITE:ownership": 2})
check("a user CAN grant a flagged-dangerous class to auto (flag, not forbid)",
      grant.auto_ceiling(owner_pub, gd, "NOTE_WRITE", {"namespace": "room-owners", "key": "d-x"}, now=now, revoked_ids=set(), expected_agent=AGENT_DID) == 2)

raised = False
try:
    grant.grant_class("ATTEST", {"job_id": "j"}, {"useful": "true"})
except ValueError:
    raised = True
check("a non-bool verdict raises in grant_class (aligned with action_string)", raised)
check("a non-bool verdict gates (auto_ceiling None) rather than mis-classing",
      grant.auto_ceiling(owner_pub, g, "ATTEST", {"job_id": "j"}, {"useful": 1}, now=now, revoked_ids=set(), expected_agent=AGENT_DID) is None)

check("an invalid (uppercase) namespace is NOT benign 'note'",
      grant.grant_class("NOTE_WRITE", {"namespace": "DID", "key": "k"}) == "NOTE_WRITE:unknown")
check("the conservative unknown note class is dangerous", grant.is_dangerous("NOTE_WRITE:unknown"))

_, OTHER_AGENT = did.generate()
check("a built grant carries the agent did", g["agent_did"] == AGENT_DID)
check("a grant bound to one agent does NOT verify for another agent",
      not grant.verify_grant(owner_pub, g, now=now, revoked_ids=set(), expected_agent=OTHER_AGENT))
check("a missing expected_agent is a reject, not a trust",
      not grant.verify_grant(owner_pub, g, now=now, revoked_ids=set(), expected_agent=None))
tampered_agent = dict(g); tampered_agent["agent_did"] = OTHER_AGENT
check("tampering the bound agent breaks the signature",
      not grant.verify_grant(owner_pub, tampered_agent, now=now, revoked_ids=set(), expected_agent=OTHER_AGENT))
_agent_raised = False
try:
    grant.build_grant(owner_priv, "g-noa", "", 1000, 100000, ALLOW)
except ValueError:
    _agent_raised = True
check("build_grant refuses an empty agent_did", _agent_raised)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
