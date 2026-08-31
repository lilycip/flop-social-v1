"""Golden GATEWAY signing vectors from the AUDITED shared/ code, for the TS gateway port.

Run from flop-social-v1:  python agent/tools/gen_gateway_vectors.py
Writes agent/vectors/gateway-vectors.json.

The gateway signs three shapes: a kibble work line over message_sig_input("kibble", nonce,
single_line(line)), our own identity note over note_sig_input(ns, key, nonce, value), and a
SIGNED chat SAY over message_sig_input(room, nonce, single_line(text)).
The TS port must reproduce the action string, the swept text, the signed bytes, AND the
signature byte-for-byte. Includes the key-format vector (raw seed wrapped as pkcs8 imports to a
key that signs identically; the spike proved this on workerd) and single_line parity vectors.
"""
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared import action, did, protocol

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "vectors", "gateway-vectors.json")

PKCS8_PREFIX = "302e020100300506032b657004220420"

NBSP = chr(0x00A0)
LS = chr(0x2028)
PS = chr(0x2029)
BOM = chr(0xFEFF)
RLO = chr(0x202E)
ZWSP = chr(0x200B)
EMOJI = chr(0x1F600)


def priv_from_seed(seed_byte):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def hexs(b):
    return b.hex()


def kibble_vec(priv, verb, target, verdict, nonce):
    line = action.action_string(verb, target, verdict)
    swept = protocol.single_line(line)
    sig_input = protocol.message_sig_input("kibble", nonce, swept)
    sig = did.sign_b64url(priv, sig_input)
    return {
        "verb": verb, "target": target, "verdict": verdict, "nonce": str(nonce),
        "action_string": line, "swept": swept,
        "sig_input_utf8": sig_input.decode("utf-8"), "signature": sig,
    }


def sw(raw):
    return {"raw": raw, "swept": protocol.single_line(raw)}


def main():
    idkey = priv_from_seed(7)
    our_did = did.did_from_priv(idkey)
    our_pub = did.pub_raw(idkey)
    ns = did.did_note_ns(our_did)
    shard, key = did.note_shard_key(our_did)

    from shared import grant as grantmod
    owner = priv_from_seed(1)
    owner_did = grantmod.did.did_from_priv(owner)
    owner_pub = grantmod.did.pub_raw(owner)
    gw_grant = grantmod.build_grant(
        owner, "g-gw", our_did, 1000, 4000000000,
        {"CLAIM": 3, "RESULT": 3, "ATTEST:useful:board-match": 2, "ATTEST:not": 2,
         "NOTE_WRITE:identity": 1, "SAY": 10}, window=86400)

    rh_a = "a" * 64
    kibble_vectors = [
        kibble_vec(idkey, "CLAIM", {"job_id": "job-abc123"}, None, 1),
        kibble_vec(idkey, "RESULT", {"job_id": "job-abc123", "result": "the delivered answer text"}, None, 2),
        kibble_vec(idkey, "ATTEST", {"job_id": "job-abc123", "result_hash": rh_a}, {"useful": True}, 3),
        kibble_vec(idkey, "ATTEST", {"job_id": "job-abc123", "result_hash": rh_a}, {"useful": False}, 4),
    ]

    note_value = "v1.4.0"
    note_nonce = 5
    note_sig_input = protocol.note_sig_input(ns, key, note_nonce, note_value)
    note_vector = {
        "namespace": ns, "key": key, "nonce": str(note_nonce), "value": note_value,
        "sig_input_utf8": note_sig_input.decode("utf-8"),
        "signature": did.sign_b64url(idkey, note_sig_input),
    }

    keyfmt_msg = "kibble|3|" + kibble_vectors[2]["swept"]
    keyfmt_vector = {
        "seed_hex": hexs(bytes([7]) * 32),
        "pkcs8_prefix_hex": PKCS8_PREFIX,
        "message_utf8": keyfmt_msg,
        "signature": kibble_vectors[2]["signature"],
    }
    assert keyfmt_msg == kibble_vectors[2]["sig_input_utf8"], "keyfmt message must equal the ATTEST sig input"

    say_room, say_text, say_nonce = "lobby", "hello from the agent  (signed)", 6
    say_swept = protocol.single_line(say_text)
    say_sig_input = protocol.message_sig_input(say_room, say_nonce, say_swept)
    say_vector = {
        "room": say_room, "text": say_text, "nonce": str(say_nonce), "swept": say_swept,
        "sig_input_utf8": say_sig_input.decode("utf-8"),
        "signature": did.sign_b64url(idkey, say_sig_input),
    }

    sweep_vectors = [
        sw("hello world"),
        sw("a" + chr(10) + "b" + chr(9) + "c"),
        sw("  trim me  "),
        sw("bidi" + RLO + "evil"),
        sw("zero" + ZWSP + "width"),
        sw("a" + NBSP + "b"),
        sw(NBSP + "edge" + NBSP),
        sw("a" + LS + "b"),
        sw(PS + "para" + PS),
        sw(BOM + "boom"),
        sw("boom" + BOM),
        sw("emoji" + EMOJI + "end"),
    ]

    out = {
        "note": "Golden GATEWAY signing vectors from the audited shared/ code. The TS port must "
                "reproduce action_string, single_line, the signed bytes, and the signature "
                "byte-for-byte. Regenerate with agent/tools/gen_gateway_vectors.py.",
        "identity_seed_hex": hexs(bytes([7]) * 32),
        "our_did": our_did,
        "our_pub_raw_hex": hexs(our_pub),
        "note_ns": ns,
        "note_key": key,
        "owner_pub_raw_hex": hexs(owner_pub),
        "owner_did": owner_did,
        "gw_grant": gw_grant,
        "kibble_vectors": kibble_vectors,
        "note_vector": note_vector,
        "keyfmt_vector": keyfmt_vector,
        "say_vector": say_vector,
        "sweep_vectors": sweep_vectors,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("wrote", os.path.normpath(OUT))
    print("our_did", our_did)
    print("note ns/key", ns, key)
    print("kibble_vectors", len(kibble_vectors), "sweep_vectors", len(sweep_vectors), "say ok")


if __name__ == "__main__":
    main()
