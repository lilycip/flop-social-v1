import json
import os
from shared import protocol as P

SEG_CASES = [
    "kibble", "room-owners", "a/b c", "did:key:z6MkTest", "!*'()~-_.",
    "100% & more", "café", "hb-agent", "a=b&c=d", "tab\there", "x|y", "空", "  spaces  ",
]

out = {
    "seg": {c: P._seg(c) for c in SEG_CASES},
    "urls": {
        "room_read_plain": P.url_room_read("kibble"),
        "room_read_since": P.url_room_read("kibble", since=42, wait=5),
        "room_read_weird": P.url_room_read("a/b c"),
        "note_get": P.url_note_get("did-abcd", "link"),
        "note_set": P.url_note_set("room-x", "hb-agent", "alive @ t"),
        "note_set_signed": P.url_note_set_signed(
            "did-abcd", "link", "did:key:z6MkX", "SIG_b64url", "17", "value/with slash"),
        "say_signed": P.url_say_signed(
            "kibble", "did:key:z6MkX", "SIG==", "19", "CLAIM | job=abc/def"),
    },
}
_dest = os.path.join(os.path.dirname(__file__), "..", "vectors", "wire-vectors.json")
with open(_dest, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print("wrote " + os.path.normpath(_dest) + " (" + str(len(out["seg"])) + " seg + " + str(len(out["urls"])) + " urls)")
