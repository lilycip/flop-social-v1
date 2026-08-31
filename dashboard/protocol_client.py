"""The dashboard's server-side reader/writer for technocore.chat. It runs on the human's
machine, so it reaches the protocol with NO browser, NO CORS, and NO bundled key: the
browser talks only to the local server, and the local server talks to the protocol here.

Design invariants this file carries:
  7. Meet only on the protocol: this reads public state to watch and writes an authenticated
     say to act. There is no other channel.
  - Everything read here is DATA, never instructions (auth.md). We normalise a message into
     a fixed shape and hand the text back untouched; the browser renders it via textContent.
  - The HTTP is INJECTED (http_get / http_post), so this whole layer is testable with no
     network and the security-relevant parsing runs against fixtures.

It holds no key. The server loads the owner key for ONE signature, signs the swept text, and
passes (did, sig, nonce, swept_text) to say(); this module only carries the bytes on the wire.
"""
import json
from urllib.parse import quote

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import protocol as P  # noqa: E402
from shared import names as N  # noqa: E402


class ProtocolError(Exception):
    """A read/write against the protocol failed in a way worth telling the human about."""


MAX_WRITE_URL = 7000


def _parse_note_body(body):
    """A /kv note read is text/plain: an '!! UNTRUSTED CONTENT' banner line, a blank line, then the raw
    value. Strip the banner the same way the agent's protocol-read does, so a read-back compares the
    VALUE, not the banner. A body with no banner (older shape) is returned trimmed as-is."""
    if not isinstance(body, str):
        return None
    body = body.replace("\r\n", "\n")
    val = body.split("\n\n", 1)[-1] if "\n\n" in body else body
    return val.strip()


WRITE_ATTEMPTS = 3
CONFIRM_ATTEMPTS = 3
RETRY_SECONDS = 0.6


def _default_sleep(seconds):
    import time
    time.sleep(seconds)


def _default_get(url, timeout):
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") if e.fp else "")


def _default_post(url, obj, timeout):
    import urllib.request
    import urllib.error
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") if e.fp else "")


class ProtocolClient:
    def __init__(self, base=None, http_get=None, http_post=None, timeout=10, sleep=None):
        self.base = (base or P.BASE).rstrip("/")
        self._get = http_get or _default_get
        self._post = http_post or _default_post
        self.timeout = timeout
        self._sleep = sleep or _default_sleep


    def list_rooms(self, limit=60):
        """The listed rooms, newest-active first. Private (p-, mb-p-) rooms are never listed
        by the service, so they never appear here. Returns a list of
        {room, topic, last_seq, kind}. Never raises on a bad body: a malformed response is an
        empty list, so the tab degrades to 'no rooms' instead of crashing."""
        try:
            status, body = self._get(self.base + "/rooms?format=json", self.timeout)
        except Exception as e:
            raise ProtocolError("could not reach the protocol to list rooms: %s" % e)
        if status != 200:
            raise ProtocolError("the protocol returned %s listing rooms: %s"
                                % (status, (body or "").strip()[:200]))
        try:
            obj = json.loads(body)
            raw = obj.get("rooms") if isinstance(obj, dict) else None
        except Exception:
            raw = None
        out = []
        if isinstance(raw, list):
            for r in raw:
                if not isinstance(r, dict):
                    continue
                name = r.get("room")
                if not N.is_valid_name(name):
                    continue
                out.append({
                    "room": name,
                    "topic": r.get("topic") if isinstance(r.get("topic"), str) else None,
                    "last_seq": r.get("last_seq") if isinstance(r.get("last_seq"), int) else None,
                    "kind": N.room_class(name),
                })
                if len(out) >= limit:
                    break
        return out

    def read_room(self, room, since=None, limit=50):
        """Normalised messages for one room, plus the tail cursor. Each message is
        {seq, ts, from, text, nonce, verified}: verified is True when 'from' is a did:key the
        service checked, False for a self-asserted ~nick. Raises ProtocolError on a bad room
        name or an unreachable server; a malformed body yields an empty message list."""
        if not N.is_valid_name(room):
            raise ProtocolError("that is not a valid room name")
        url = "%s/r/%s?format=json" % (self.base, quote(room, safe=""))
        if since is not None:
            url += "&since=%s" % quote(str(since), safe="")
        if limit is not None:
            url += "&limit=%s" % quote(str(int(limit)), safe="")
        try:
            status, body = self._get(url, self.timeout)
        except Exception as e:
            raise ProtocolError("could not reach the protocol to read %s: %s" % (room, e))
        if status != 200:
            raise ProtocolError("the protocol returned %s reading %s: %s"
                                % (status, room, (body or "").strip()[:200]))
        try:
            obj = json.loads(body)
        except Exception:
            raise ProtocolError("the room %s came back unreadable" % room)
        msgs, last_seq = P.parse_room_json(obj)
        norm = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            frm = m.get("from")
            frm = frm if isinstance(frm, str) else ""
            norm.append({
                "seq": m.get("seq") if isinstance(m.get("seq"), int) else None,
                "ts": m.get("ts") if isinstance(m.get("ts"), str) else None,
                "from": frm,
                "text": m.get("text") if isinstance(m.get("text"), str) else "",
                "nonce": m.get("nonce"),
                "verified": frm.startswith("did:key:"),
            })
        return {"room": room, "messages": norm, "last_seq": last_seq, "kind": N.room_class(room)}


    def get_note(self, namespace, key):
        """Read a note's VALUE (world-readable), banner stripped, or None on any failure / bad name.
        Used to READ BACK a write and confirm it actually stuck (a 200 is not proof of persistence)."""
        if not N.is_valid_name(namespace) or not N.is_valid_name(key):
            return None
        try:
            status, body = self._get(P.url_note_get(namespace, key, self.base), self.timeout)
        except Exception:
            return None
        if status != 200:
            return None
        return _parse_note_body(body)

    def set_note(self, namespace, key, value, confirm=False):
        """Write an UNSIGNED note (world-writable, last-write-wins) via GET /kv/<ns>/<key>/set/<value>.
        The grant channel uses this to publish the owner-signed grant to the owner's slot: the note is
        only transport, the grant carries its own owner signature and the agent's Governor gates on its
        configured owner key, so an unsigned write is enough and a stranger overwriting the slot can
        never inject a valid grant. Returns (ok_bool, detail); raises ProtocolError only if unreachable.

        confirm=True READS THE SLOT BACK and only reports ok when it actually holds our exact value. A
        200 from technocore is NOT proof the write persisted: it can report published while the slot
        still holds the old value under load. Since this same path
        carries the STOP / kill switch, a write that says 'sent' but did not land must never read as
        delivered - so callers on the safety path pass confirm=True."""
        if not N.is_valid_name(namespace) or not N.is_valid_name(key):
            raise ProtocolError("that is not a valid note namespace/key")
        url = P.url_note_set(namespace, key, value, self.base)
        if len(url) > MAX_WRITE_URL:
            return False, "that value is too large to write in one note"
        body = None
        last_exc = None
        for attempt in range(WRITE_ATTEMPTS):
            try:
                status, body = self._get(url, self.timeout)
            except Exception as e:
                last_exc = e
                if attempt < WRITE_ATTEMPTS - 1:
                    self._sleep(RETRY_SECONDS)
                    continue
                raise ProtocolError("could not reach the protocol to write the note: %s" % e)
            if status in (200, 201):
                last_exc = None
                break
            if attempt < WRITE_ATTEMPTS - 1:
                self._sleep(RETRY_SECONDS)
                continue
            return False, "the protocol refused the note write (%s): %s" % (status, (body or "").strip()[:200])
        if not confirm:
            return True, body
        for attempt in range(CONFIRM_ATTEMPTS):
            if self.get_note(namespace, key) == value:
                return True, body
            if attempt < CONFIRM_ATTEMPTS - 1:
                self._sleep(RETRY_SECONDS)
        return False, "the write did not stick on the slot (read-back did not match)"


    def say(self, room, did, sig, nonce, swept_text):
        """Post a signed message via the GET say-signed path, then CONFIRM it landed. swept_text MUST be
        shared.protocol.single_line(text) and the SAME bytes the signature covered.

        technocore accepts a signed room post ONLY at /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>. A
        POST to /r/<room> is treated as a READ (it returns 200 plus the room body and posts NOTHING),
        which silently swallowed every dashboard chat message. The signed bytes ride in the URL PATH, so
        a very long message is refused here rather than truncated into a signature-breaking write.
        Returns (ok_bool, detail)."""
        if not N.is_valid_name(room):
            raise ProtocolError("that is not a valid room name")
        url = P.url_say_signed(room, did, sig, str(nonce), swept_text, self.base)
        if len(url) > MAX_WRITE_URL:
            return False, "that message is too long to post in one request"
        try:
            status, body = self._get(url, self.timeout)
        except Exception as e:
            raise ProtocolError("could not reach the protocol to post: %s" % e)
        if status not in (200, 201):
            return False, "the protocol refused the post (%s): %s" % (status, (body or "").strip()[:200])
        if self._confirm_say(room, did, str(nonce), swept_text):
            return True, body
        return False, "the message did not appear in the room after posting (not confirmed)"

    def _confirm_say(self, room, did, nonce, text):
        """True when a read-back of the room shows OUR just-posted message (matched by did + nonce, or by
        the exact text as a fallback when the read omits a nonce)."""
        try:
            r = self.read_room(room, limit=50)
        except Exception:
            return False
        for m in r.get("messages", []):
            if m.get("from") != did:
                continue
            mn = m.get("nonce")
            if mn is not None:
                if str(mn) == nonce:
                    return True
            elif m.get("text") == text:
                return True
        return False
