"""The steer envelope: a human's signed authorization for ONE action, fail-closed and
replay-proof. This is the FLOP layer, not the technocore protocol; it rides inside a
protocol write once the agent trusts it.

The verifier NEVER takes an action string off the wire and never trusts a caller to
have checked the destination. It re-derives the action string AND the action's own
embedded destination from trusted (verb, target, verdict), the way the Governor already
re-derives everything (invariant 6). An envelope is trusted only if ALL hold:
  - it carries a signature, a channel, a nonce, and an expiry,
  - the caller supplied a clock (now), a replay store (seen_nonces), and the TRUE
    destination the write is about to land in,
  - the signed channel equals that destination,
  - AND, for a verb whose action names its own destination (SAY room, NOTE_WRITE ns),
    that embedded destination equals the channel too, so the write cannot land anywhere
    other than where the action itself says,
  - it has not expired and its canonical nonce has not been seen,
  - the signature verifies, under the human's key, over the reconstructed message
        steer|<channel>|<action_string>|nonce:<n>|exp:<e>

Design choices, each closing a class of hole found on the old build or in review:
  1. One carrier of meaning: the action string (shared/action.py) holds a hash of every
     content field, so nothing is bound in one place and forgotten in another.
  2. Destination is enforced HERE, in one place, against both the caller's true target
     and the action's own embedded location. Not an unwritten caller contract.
  3. Nonce and expiry are CANONICALISED to a decimal string (canon_int) before both the
     signed bytes and the replay test, so int 1 and str "1" cannot miss each other in
     the seen-set, and a 19-digit nonce (legal, over JS safe-int) stays a string.

Fail-closed means a missing field, clock, store, or destination is a REJECT, never a
trust. verify_steer never raises: a target that cannot even build an action is a reject.
"""
from . import action, did
from .canon import canon_int

__all__ = ["canon_int", "steer_message", "build_steer", "verify_steer"]


def steer_message(channel, action_string, nonce, expiry):
    """The exact bytes the human key signs. nonce and expiry are canonicalised so both
    sides, in either language, produce identical bytes."""
    return ("steer|%s|%s|nonce:%s|exp:%s"
            % (channel or "", action_string or "",
               canon_int(nonce, "nonce"), canon_int(expiry, "expiry"))).encode("utf-8")


def build_steer(priv_human, channel, action_string, nonce, expiry):
    """Sign an authorization for exactly this action in exactly this channel. Returns
    the on-wire envelope with nonce and expiry in canonical string form. The action
    string is NOT put on the wire: the verifier re-derives it, so a tampered wire copy
    could only fail the signature. The caller must have built action_string for a target
    whose embedded destination (if any) equals channel; verify_steer enforces that."""
    if not channel:
        raise ValueError("a steer must name its channel; an unscoped approval is refused")
    n, e = canon_int(nonce, "nonce"), canon_int(expiry, "expiry")
    sig = did.sign_b64url(priv_human, steer_message(channel, action_string, n, e))
    return {"channel": channel, "signature": sig, "nonce": n, "expiry": e}


def verify_steer(human_pub, steer, verb, target, destination,
                 verdict=None, now=None, seen_nonces=None):
    """True iff steer is a present, unexpired, unseen, validly-signed authorization by
    human_pub over the action RE-DERIVED from (verb, target, verdict), whose signed
    channel equals the true destination AND the action's own embedded destination.

    Never raises. destination, now, and seen_nonces are all REQUIRED; a None is a reject,
    not a trust. On success the canonical nonce is recorded so it cannot be replayed in
    any equivalent form.

    For a verb with no embedded destination (ATTEST/RESULT/CLAIM target a job, not a
    room), pass the TRUE room the write lands in as destination; do not pass the
    envelope's own channel, or the destination check becomes a tautology."""
    if not isinstance(steer, dict):
        return False
    sig = steer.get("signature")
    channel = steer.get("channel")
    nonce = steer.get("nonce")
    expiry = steer.get("expiry")
    if not sig or not channel or nonce is None or expiry is None:
        return False
    if now is None or seen_nonces is None or destination is None:
        return False
    try:
        action_string = action.action_string(verb, target, verdict)
        embedded = action.embedded_destination(verb, target)
    except (ValueError, AttributeError, TypeError):
        return False
    if channel != destination:
        return False
    if embedded is not None and embedded != channel:
        return False
    try:
        cn, ce = canon_int(nonce, "nonce"), canon_int(expiry, "expiry")
    except ValueError:
        return False
    try:
        if int(ce) < int(now):
            return False
    except (TypeError, ValueError):
        return False
    if cn in seen_nonces:
        return False
    msg = steer_message(channel, action_string, cn, ce)
    if not (human_pub and did.verify_b64url(human_pub, sig, msg)):
        return False
    seen_nonces.add(cn)
    return True
