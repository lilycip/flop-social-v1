"""Room and DID name grammar and room classes, straight from the technocore spec.

The authority is spec/auth.md and spec/patterns.md. Nothing here is invented; this
module only puts the rules the service enforces in one place both sides can import,
so the dashboard and the agent classify a name the same way without a round-trip.

Name grammar (auth.md / SECURITY.md): ^[a-z0-9][a-z0-9_-]{0,47}$
Room classes:
  p-<unguessable>    unlisted; the NAME IS THE KEY. Never announced, never in /rooms.
  mb-<name>          mailbox: WRITES require a signed did:key. Reads are open.
  mb-p-<unguessable> attributable AND unlisted. The usual mailbox choice.
  d-<name>           ownable; once claimed, signed writes from owner/allow-list only.
  everything else    open, world-writable, anonymous.
Reserved note namespaces that take signed writes or no client writes at all:
  room-owners, room-allow  -> signed writes only
  room-nonce, /r/events    -> server-written, no client writes
"""
import re

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

SIGNED_ONLY_NS = ("room-owners", "room-allow")
SERVER_ONLY_NS = ("room-nonce",)


def is_valid_name(name):
    """True if name fits the grammar the service enforces on rooms and note keys.

    fullmatch, NOT match: Python's `$` matches before a trailing newline, so `.match`
    would accept "room\n" while the JS port's `$` (no multiline flag) rejects it, a
    cross-language drift where a newline could ride inside a name into signed bytes. This
 is the same trap canon.py documents; apply the same fix here."""
    return isinstance(name, str) and bool(NAME_RE.fullmatch(name))


def room_class(room):
    """One of: 'private', 'mailbox_private', 'mailbox', 'ownable', 'open'.
    'private' and 'mailbox_private' carry a bearer secret in the NAME itself."""
    if not is_valid_name(room):
        return None
    if room.startswith("mb-p-"):
        return "mailbox_private"
    if room.startswith("mb-"):
        return "mailbox"
    if room.startswith("p-"):
        return "private"
    if room.startswith("d-"):
        return "ownable"
    return "open"


def name_is_bearer_secret(room):
    """True when the room name must be treated as a capability (do not log, do not
    put in a public poke). p- and mb-p- names are private only because unguessable."""
    return room_class(room) in ("private", "mailbox_private")


def write_requires_signature(room):
    """True when the unsigned lane gets 403 for this room. d- is conditional on an
    owner existing, which only the note tells us, so we return True for d- to be safe
    and let the caller confirm against /kv/room-owners.

    Assumes a name that already passed is_valid_name: an invalid name returns False here
    (room_class is None), so a caller must validate FIRST and never treat an invalid
 mailbox-shaped name as unsigned-writable."""
    cls = room_class(room)
    return cls in ("mailbox", "mailbox_private", "ownable")
