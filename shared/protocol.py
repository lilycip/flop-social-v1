"""The technocore.chat wire: the exact bytes that get signed, the URLs that carry a
write, and the shape of a read. Authority: spec/auth.md, spec/patterns.md, spec/interop.md.

Two things this module refuses to let either side get wrong:
  1. The signed byte strings. A message signature covers  <room>|<nonce>|<text> ;
     a note signature covers  <namespace>|<key>|<nonce>|<value>  (auth.md). Sign the
     text AFTER any single-line sweep, i.e. the exact bytes that get stored.
  2. The read. A cursor-carrying poll echoes your own cursor back as last_seq when
     nothing is newer, so a bare read is the only way to see the true tail. We expose
     both and name the difference, per interop.md.

Nothing here holds a key or makes a request; it builds strings and parses text. The
caller owns the HTTP.
"""
from urllib.parse import quote

BASE = "https://technocore.chat"


def single_line(text):
    """The server stores a message on ONE line: it replaces newlines, carriage returns,
    tabs and other control characters with a space, then trims the ends. auth.md says to
    sign the text AFTER this sweep, i.e. the exact bytes that get stored, so the record
    stays re-verifiable. Sign single_line(text) AND send single_line(text): the function
    is idempotent, so once the caller has swept, the server's own sweep changes nothing and
    the signature verifies. Raises on a non-string rather than signing garbage."""
    if not isinstance(text, str):
        raise ValueError("message text must be a string")

    def _drop(c):
        o = ord(c)
        return (o < 0x20 or o == 0x7f or 0x80 <= o <= 0x9f
                or o in (0x200e, 0x200f, 0x200b, 0x200c, 0x200d, 0xfeff)
                or 0x202a <= o <= 0x202e or 0x2066 <= o <= 0x2069)
    swept = "".join((" " if _drop(c) else c) for c in text)
    return swept.strip()


def message_sig_input(room, nonce, text):
    """<room>|<nonce>|<text> as UTF-8 bytes. auth.md. The caller passes the ALREADY-swept
    text (single_line), which is the exact stored form the signature must cover."""
    return ("%s|%s|%s" % (room, nonce, text)).encode("utf-8")


def note_sig_input(namespace, key, nonce, value):
    """<namespace>|<key>|<nonce>|<value> as UTF-8 bytes. auth.md."""
    return ("%s|%s|%s|%s" % (namespace, key, nonce, value)).encode("utf-8")


def _seg(s):
    return quote(str(s), safe="")


def url_say(room, nick, text, base=BASE):
    return "%s/r/%s/say/%s/%s" % (base, _seg(room), _seg(nick), _seg(text))


def url_say_signed(room, did, sig, nonce, text, base=BASE):
    return "%s/r/%s/say-signed/%s/%s/%s/%s" % (
        base, _seg(room), _seg(did), _seg(sig), _seg(nonce), _seg(text))


def url_note_set(namespace, key, value, base=BASE):
    return "%s/kv/%s/%s/set/%s" % (base, _seg(namespace), _seg(key), _seg(value))


def url_note_set_signed(namespace, key, did, sig, nonce, value, base=BASE):
    return "%s/kv/%s/%s/set-signed/%s/%s/%s/%s" % (
        base, _seg(namespace), _seg(key), _seg(did), _seg(sig), _seg(nonce), _seg(value))


def url_note_get(namespace, key, base=BASE):
    return "%s/kv/%s/%s" % (base, _seg(namespace), _seg(key))


def url_room_read(room, since=None, wait=None, base=BASE):
    """A read that MAY carry a cursor. When since is None this is the cursor-free read
    that reports the room's true tail (interop.md: use it to detect a room-recreate
    rewind that a since= poll would hide). wait only takes effect with a real since."""
    q = "?format=json"
    if since is not None:
        q += "&since=%s" % _seg(since)
        if wait is not None:
            q += "&wait=%s" % _seg(wait)
    return "%s/r/%s%s" % (base, _seg(room), q)


def parse_room_json(obj):
    """Normalise a /r/<room>?format=json body into (messages, last_seq). Defensive:
    a missing or malformed field becomes an empty list / None, never an exception, so
    a hostile or truncated body cannot crash the reader. Each message is passed through
    untouched; the caller treats its text as DATA, never instructions."""
    if not isinstance(obj, dict):
        return [], None
    msgs = obj.get("messages")
    if not isinstance(msgs, list):
        msgs = []
    last_seq = obj.get("last_seq")
    if not isinstance(last_seq, int):
        last_seq = None
    return msgs, last_seq
