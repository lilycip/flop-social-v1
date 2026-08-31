"""shared/ - the wire contract, defined ONCE, imported by both sides.

The dashboard (the human's machine) builds and signs; the agent (on Cloudflare) verifies
and re-derives. Neither side may redefine any of this; that is how the partial-binding
class of hole stays closed.

  names     room / DID name grammar and room classes (spec/auth.md, patterns.md)
  did       Ed25519 did:key, signatures, fingerprint, the sharded note path
  canon     canonical integer literals shared by every signed envelope
  protocol  the technocore wire: signed byte strings, write URLs, the read format
  action    THE canonical action string: an action's complete, bindable meaning
  steer     the human's fail-closed, replay-proof approval over ONE action (the gated path)
  grant     the human's signed standing permission slip for AUTO action (the autonomy spine)
"""
from . import names, did, canon, protocol, action, steer, grant  # noqa: F401

__all__ = ["names", "did", "canon", "protocol", "action", "steer", "grant"]
