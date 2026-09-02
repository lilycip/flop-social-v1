"""The standing GRANT: a human's signed permission slip that lets their agent act on AUTO
inside bounds the user chose. This is the spine of the autonomy model:
the agent runs alone; the human does not approve each act.

the owner's rules:
  - The agent runs on auto, INSIDE the grant. What is not in the grant is gated (a human
    approves it through the steer path, shared/steer.py).
  - The grant is the USER'S. Each user sets which classes run on auto, and the per-class
    ceiling, and the expiry. We ship the mechanism and defaults; we bake in no numbers.
  - Safe-by-default: the dangerous classes are NOT auto unless the user deliberately adds
    them. The grant is an explicit ALLOWLIST, so absence means gated, never allowed.
  - Revoke is first-class: one revoked grant_id drops everything back to gating; a user
    re-signs a new grant to change any single class or ceiling.

A grant is:
    {grant_id, owner_did, issued, expiry, allow: {klass: ceiling_per_day, ...}, signature}
signed by the owner key over a canonical message. The CEILING COUNTER (how many of a class
ran today) is the agent Governor's own state, not carried here; this module answers only
"does a valid grant permit this class, and up to what ceiling". The Governor compares its
counter to that ceiling.

NECESSARY, NOT SUFFICIENT. A ceiling from auto_ceiling means "the user granted this CLASS on
auto". It does NOT mean run it. The Governor must still apply, on top:
  - the daily counter vs the ceiling,
  - the content gates that are not class-derivable: money, anything naming a real person,
    the egress scanner, a canary. Any of those fires -> gate, even for a granted class.
A grant lifts the class-level bar; it never overrides a content-level stop. Some dangerous
kinds (money, naming a person) are content properties with no class of their own, so they are
gated by those checks regardless of what the allowlist says.
"""
import re

from . import action, did, names
from .canon import canon_int

_KLASS_RE = re.compile(r"[A-Za-z0-9:_-]{1,64}")
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

DEFAULT_WINDOW_SECONDS = 86400

DANGEROUS_CLASSES = frozenset({
    "ATTEST:useful:no-board-match",
    "NOTE_WRITE:identity",
    "NOTE_WRITE:ownership",
})


def is_dangerous(klass):
    """True if a class must carry a clear danger warning before a user sets it to auto (it is
    never forbidden, only flagged). Unknown, unclassified, or non-string classes are dangerous
    by default (conservative)."""
    if not isinstance(klass, str):
        return True
    return (klass in DANGEROUS_CLASSES
            or klass.startswith("OTHER:")
            or klass.endswith(":unknown"))


def grant_class(verb, target=None, verdict=None, board_match=False):
    """The AUTONOMY CLASS of an action: what the grant grants, at the safety-relevant level
    (never the instance, never content). Deterministic; the dashboard and the Governor both
    compute it the same way. The dangerous classes are named distinctly so a user's allowlist
    can include or exclude each on its own."""
    verb = (verb or "").upper()
    t = action._as_target(target)
    if verb == "ATTEST":
        useful = action._useful(verdict)
        if useful:
            return "ATTEST:useful:board-match" if board_match else "ATTEST:useful:no-board-match"
        return "ATTEST:not"
    if verb == "SAY":
        return "SAY"
    if verb == "NOTE_WRITE":
        ns = (t.get("namespace") or "")
        if not names.is_valid_name(ns):
            return "NOTE_WRITE:unknown"
        if ns == "did" or ns.startswith("did-"):
            return "NOTE_WRITE:identity"
        if ns in ("room-owners", "room-allow"):
            return "NOTE_WRITE:ownership"
        return "NOTE_WRITE:note"
    if verb == "RESULT":
        return "RESULT"
    if verb == "CLAIM":
        return "CLAIM"
    return "OTHER:" + (verb or "UNKNOWN")


def _canon_allow(allow):
    """Canonicalise the allowlist {klass: ceiling} to a deterministic string, klasses sorted,
    each validated, each ceiling a canonical non-negative integer."""
    if not isinstance(allow, dict):
        raise ValueError("allow must be a dict of {klass: ceiling}")
    parts = []
    for k in sorted(allow):
        if not (isinstance(k, str) and _KLASS_RE.fullmatch(k)):
            raise ValueError("bad class name: %r" % (k,))
        parts.append("%s=%s" % (k, canon_int(allow[k], "ceiling")))
    return ",".join(parts)


def grant_message(grant_id, owner_did, agent_did, issued, expiry, window, allow):
    """The exact bytes the owner key signs. It binds BOTH parties: the owner_did (who granted)
    AND the agent_did (who it is granted TO), so a grant is never a bearer token that any agent
 could present. The window (seconds a ceiling is 'per') is bound here too,
    so 'per day' is what the user signed, not what the Governor decides a day is."""
    if not (isinstance(grant_id, str) and _ID_RE.fullmatch(grant_id)):
        raise ValueError("grant_id must match %s" % _ID_RE.pattern)
    if not (isinstance(agent_did, str) and agent_did):
        raise ValueError("agent_did must be a non-empty did:key string")
    return ("grant|%s|%s|agent:%s|issued:%s|exp:%s|window:%s|allow:%s"
            % (grant_id, owner_did, agent_did, canon_int(issued, "issued"),
               canon_int(expiry, "expiry"), canon_int(window, "window"),
               _canon_allow(allow))).encode("utf-8")


def build_grant(priv_owner, grant_id, agent_did, issued, expiry, allow, window=DEFAULT_WINDOW_SECONDS):
    """Sign a grant FOR a specific agent. allow is {klass: ceiling_per_window}; an EMPTY allow
    is a valid grant that authorizes nothing on auto (everything gated), the safe default state.
    agent_did is the identity this grant authorizes and is BOUND into the signature, so the grant
    cannot be re-used for a different agent. window is the seconds a ceiling counts over."""
    owner_did = did.did_from_priv(priv_owner)
    msg = grant_message(grant_id, owner_did, agent_did, issued, expiry, window, allow)
    sig = did.sign_b64url(priv_owner, msg)
    return {"grant_id": grant_id, "owner_did": owner_did, "agent_did": agent_did,
            "issued": canon_int(issued, "issued"), "expiry": canon_int(expiry, "expiry"),
            "window": canon_int(window, "window"), "allow": dict(allow), "signature": sig}


def verify_grant(owner_pub, grant, now=None, revoked_ids=None, expected_agent=None):
    """True iff grant is a present, unexpired, un-revoked grant validly signed by owner_pub,
    whose claimed owner_did resolves to owner_pub AND whose bound agent_did equals expected_agent.
    Never raises. now, revoked_ids and expected_agent are ALL REQUIRED; a missing clock, a missing
    revocation set, or a missing expected agent is a reject, not a trust (a grant without any one
    of these checks would be an un-revocable or bearer permission)."""
    if not isinstance(grant, dict):
        return False
    if owner_pub is None or now is None or revoked_ids is None or not expected_agent:
        return False
    sig = grant.get("signature")
    owner_did = grant.get("owner_did")
    grant_id = grant.get("grant_id")
    agent_did = grant.get("agent_did")
    # These come straight from a world-readable / on-disk file. Require the exact types we use them as,
    # so a crafted non-string (e.g. a list grant_id -> unhashable in the revoked-set test) returns False
    # rather than raising out of this "never raises" function.
    if not (isinstance(sig, str) and isinstance(owner_did, str)
            and isinstance(grant_id, str) and isinstance(agent_did, str)):
        return False
    if not sig or not owner_did or not grant_id or not agent_did:
        return False
    if agent_did != expected_agent:
        return False
    try:
        if did.pub_raw_from_did(owner_did) != owner_pub:
            return False
    except Exception:
        return False
    if grant_id in revoked_ids:
        return False
    try:
        if int(canon_int(grant.get("expiry"), "expiry")) < int(now):
            return False
        msg = grant_message(grant_id, owner_did, agent_did, grant.get("issued"),
                            grant.get("expiry"), grant.get("window"), grant.get("allow") or {})
    except (ValueError, TypeError):
        return False
    return did.verify_b64url(owner_pub, sig, msg)


def authorized_ceiling(grant, klass):
    """The per-window ceiling this grant sets for klass, or None if the class is not on the
    allowlist OR its ceiling is zero (both mean gated). A zero ceiling is indistinguishable
    from 'not granted' in intent, so it collapses to None here rather than tempting a caller
 to read a non-None number as permission. Call ONLY on a verified grant.
    The Governor still enforces its own running counter with strict counter < ceiling."""
    a = grant.get("allow") or {}
    c = a.get(klass)
    if c is None:
        return None
    try:
        v = int(canon_int(c, "ceiling"))
    except ValueError:
        return None
    return v if v > 0 else None


def auto_ceiling(owner_pub, grant, verb, target=None, verdict=None, board_match=False,
                 now=None, revoked_ids=None, expected_agent=None):
    """The single safe entry the Governor calls: verify the grant (including that it is bound to
    THIS agent), class the action, and return its ceiling, or None if the action is gated (no
    valid grant, wrong agent, or class not on the allowlist). Never raises. The Governor then
    compares its own daily counter to the ceiling. None ALWAYS means gate; the Governor must
    never treat a None as permission."""
    if not verify_grant(owner_pub, grant, now=now, revoked_ids=revoked_ids, expected_agent=expected_agent):
        return None
    try:
        klass = grant_class(verb, target, verdict, board_match)
    except Exception:
        return None
    return authorized_ceiling(grant, klass)
