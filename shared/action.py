"""THE canonical action string: the one place an action's COMPLETE meaning is defined.

This module exists because the old repo bled holes for one reason. Its build_action
bound job_id and the verdict but not result_hash, so a compromised agent could keep a
human's genuine approval and swap WHICH delivery it praised. Close job_id, the next
unbound field is the new hole. The fix is not another patch; it is a rule:

  Every field that changes what an action DOES is inside the action string, or the
  action cannot be signed. There is NO generic fallback verb. An unknown verb raises,
  because an action we cannot fully bind must never become signable.

Binding is not consent. The action string binds content by HASH, which stops the agent
swapping content AFTER approval. It does nothing about the human approving content they
never SAW. So the human must be shown the exact bytes whose hash is bound, BEFORE they
sign. bound_content() below returns those bytes and refuses to omit them; the dashboard
approval card must render every item it returns, in full. For an ATTEST, that means the
delivery being vouched for, verified to hash to the bound result_hash.

Everything downstream derives from this one module:
  - what the human is SHOWN (bound_content, describe),
  - what the browser commits to (action_commit),
  - what the human key signs (inside the steer envelope, shared/steer.py),
  - what the agent's Governor RE-DERIVES from its own trusted fields and re-checks.

Free-form content enters the action string only as a SHA-256 hash, so it can never
forge the '|' separator. Token fields (job_id, room, namespace, key) are constrained to
the name grammar and validated here. result_hash is validated as 64-hex. Anything that
fails validation raises rather than being bound loosely.

Keep this byte-for-byte identical to the browser's JS port. shared/vectors.json is the
golden set both implementations must reproduce exactly.
"""
import hashlib

from . import names

VERSION = "v2"
KNOWN_VERBS = ("ATTEST", "RESULT", "CLAIM", "NOTE_WRITE", "SAY")

_HEX = set("0123456789abcdef")


def sha256_hex(s):
    """SHA-256 hex of a UTF-8 string. Callers pass strings; use _content_hash for the
    action fields so a non-string is a hard error, not a silent cross-language divergence."""
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def is_sha256_hex(h):
    return isinstance(h, str) and len(h) == 64 and all(c in _HEX for c in h)


def _as_target(target):
    """target must be a dict (None means empty). A non-dict is a hard ValueError, never
    an AttributeError from a later .get(), so callers (the steer trust gate included) get
    one clean reject shape from every entry point."""
    if target is None:
        return {}
    if not isinstance(target, dict):
        raise ValueError("target must be a dict, got %s" % type(target).__name__)
    return target


def _as_verdict(verdict):
    if verdict is None:
        return {}
    if not isinstance(verdict, dict):
        raise ValueError("verdict must be a dict, got %s" % type(verdict).__name__)
    return verdict


def _tok(label, value):
    if not names.is_valid_name(value):
        raise ValueError("%s must match the name grammar ^[a-z0-9][a-z0-9_-]{0,47}$, "
                         "got %r" % (label, value))
    return value


def _rh(label, value):
    if not is_sha256_hex(value):
        raise ValueError("%s must be a 64-char lowercase sha256 hex, got %r"
                         % (label, value))
    return value


def _require_str(label, value):
    """A content field must be a string (None means empty). Any other type raises, so
    Python and the JS port cannot disagree on how a list/dict/number coerces."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("%s must be a string, got %s" % (label, type(value).__name__))
    return value


def _content_hash(label, value):
    return sha256_hex(_require_str(label, value))


def _useful(verdict):
    """ATTEST verdict must be a REAL boolean. A truthy string like 'false' must never
    become a positive reputation vote."""
    u = _as_verdict(verdict).get("useful")
    if not isinstance(u, bool):
        raise ValueError("ATTEST verdict.useful must be a real boolean, got %r" % (u,))
    return u


def action_string(verb, target, verdict=None):
    """The complete canonical meaning of an action. Raises on anything it cannot fully
    bind. target is a dict; verdict is a dict like {'useful': True} for ATTEST."""
    verb = (verb or "").upper()
    t = _as_target(target)

    if verb == "ATTEST":
        job = _tok("job_id", t.get("job_id"))
        v = "useful" if _useful(verdict) else "not"
        rh = _rh("result_hash", t.get("result_hash"))
        return "ATTEST %s | job:%s | verdict:%s | rh:%s" % (VERSION, job, v, rh)

    if verb == "RESULT":
        job = _tok("job_id", t.get("job_id"))
        if t.get("result_hash") is not None:
            rh = _rh("result_hash", t.get("result_hash"))
        else:
            rh = _content_hash("result", t.get("result"))
        return "RESULT %s | job:%s | rh:%s" % (VERSION, job, rh)

    if verb == "CLAIM":
        job = _tok("job_id", t.get("job_id"))
        return "CLAIM %s | job:%s" % (VERSION, job)

    if verb == "NOTE_WRITE":
        ns = _tok("namespace", t.get("namespace"))
        key = _tok("key", t.get("key"))
        vh = _content_hash("value", t.get("value"))
        return "NOTE_WRITE %s | ns:%s | key:%s | vh:%s" % (VERSION, ns, key, vh)

    if verb == "SAY":
        room = _tok("room", t.get("room"))
        th = _content_hash("text", t.get("text"))
        return "SAY %s | room:%s | th:%s" % (VERSION, room, th)

    raise ValueError("unknown verb %r: refusing to build an under-bound action. Add an "
                     "explicit complete binding for it here first." % verb)


def result_hash_of(body):
    """The canonical result hash of a delivery body: the value an ATTEST binds as
    result_hash and a RESULT binds for the same bytes. One hash, one place."""
    return _content_hash("body", body)


def action_commit(verb, target, verdict=None):
    """What the browser commits to: sha256 of the exact action string it will sign.
    The local server re-derives the action string from the pending item and refuses if
    its own sha256 does not equal this. Defence in depth on top of the server re-deriving
    the action itself (never trusting a client-supplied action string)."""
    return sha256_hex(action_string(verb, target, verdict))


def embedded_destination(verb, target):
    """The destination a verb NAMES inside its own action string, or None for verbs
    whose destination is not part of their semantic identity (ATTEST/RESULT/CLAIM target
    a job, and where their write lands is a separate fact the steer's channel carries).
    The caller cross-checks this against the steer channel so the two never disagree."""
    verb = (verb or "").upper()
    t = _as_target(target)
    if verb == "SAY":
        return t.get("room")
    if verb == "NOTE_WRITE":
        return t.get("namespace")
    return None


def bound_content(verb, target):
    """The full, human-readable bytes whose hash the action binds. The approval card MUST
    display every item returned here, in full, next to what it is. This function REFUSES
    to omit content: if the displayable bytes are not present it raises, so the dashboard
    physically cannot render an approval card that hides what the human is vouching for.

    Returns a list of (label, full_text) pairs. Empty only for CLAIM, which binds no
    free content. For ATTEST the delivery body must be supplied (target['delivery_body'])
    and is verified to hash to the bound result_hash before it is shown."""
    verb = (verb or "").upper()
    t = _as_target(target)
    if verb == "SAY":
        return [("message text", _require_str("text", t.get("text")))]
    if verb == "NOTE_WRITE":
        return [("note value", _require_str("value", t.get("value")))]
    if verb == "RESULT":
        return [("delivery body", _require_str("result", t.get("result")))]
    if verb == "ATTEST":
        body = t.get("delivery_body")
        if body is None:
            raise ValueError("ATTEST approval requires target['delivery_body']: the human "
                             "must read the delivery named by result_hash before voting. "
                             "Fetch it, then pass it here.")
        body = _require_str("delivery_body", body)
        if sha256_hex(body) != t.get("result_hash"):
            raise ValueError("delivery_body does not hash to result_hash; the fetched "
                             "delivery is not the one being voted on. Refusing to show it.")
        return [("delivery being vouched for", body)]
    if verb == "CLAIM":
        return []
    raise ValueError("unknown verb %r: cannot describe content for an unbindable action." % verb)


def approval_view(verb, target, verdict=None):
    """Everything the approval card needs, all derived from ONE target in ONE call, so
    the bytes shown to the human (content) and the bytes bound by the signature
    (action_string / action_commit) can never come from two different targets. The
    dashboard MUST build its card from this, not by calling the pieces separately with
 possibly-different inputs. Raises if the action cannot be fully bound
    or its content cannot be shown."""
    return {
        "heading": describe(verb, target, verdict),
        "content": bound_content(verb, target),
        "action_string": action_string(verb, target, verdict),
        "action_commit": action_commit(verb, target, verdict),
        "embedded_destination": embedded_destination(verb, target),
    }


def describe(verb, target, verdict=None):
    """A short human sentence for the approval card HEADING. It names the action; it is
    NOT a substitute for showing the content. The card must render bound_content() in
    full underneath this line. Kept next to the binding so they cannot drift apart."""
    verb = (verb or "").upper()
    t = _as_target(target)
    if verb == "ATTEST":
        v = "USEFUL" if _as_verdict(verdict).get("useful") is True else "NOT useful"
        return "Vote that job %s's delivery is %s (you are reading the exact delivery below)." % (
            t.get("job_id", "?"), v)
    if verb == "RESULT":
        return "Post this delivery for job %s (shown in full below)." % t.get("job_id", "?")
    if verb == "CLAIM":
        return "Claim job %s as the worker." % t.get("job_id", "?")
    if verb == "NOTE_WRITE":
        return "Write note %s/%s with the value shown below." % (
            t.get("namespace", "?"), t.get("key", "?"))
    if verb == "SAY":
        return "Say the message shown below in room %s." % t.get("room", "?")
    return "Unknown action (%s) - cannot be approved." % verb
