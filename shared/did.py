"""did:key (Ed25519) identity primitives, per spec/auth.md and spec/patterns.md.

A did:key IS an Ed25519 public key: multicodec ed25519-pub (0xed 0x01) then the 32
raw bytes, base58btc-encoded with a 'z' multibase prefix, so it starts did:key:z6Mk.
Nothing is registered anywhere; resolution is offline and this file is the resolver.

Wire signature encoding is base64url, unpadded, 86 chars for a 64-byte signature
(auth.md). We never store or transmit a private key from this module; callers hold
the Ed25519PrivateKey object and pass it in to sign.

The DID note lives at /kv/did-<shard>/<key>, where the fingerprint is the first 16
hex of SHA-256 of the full did:key string, shard is its first 2 chars, key the rest.
"""
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ED25519_MULTICODEC = b"\xed\x01"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_DID_PREFIX = "did:key:z"


def _b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def _b58decode(s):
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("not base58btc: %r" % ch)
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def generate():
    """A fresh Ed25519 keypair. Returns (private_key_obj, did_str)."""
    priv = Ed25519PrivateKey.generate()
    return priv, did_from_priv(priv)


def pub_raw(priv):
    return priv.public_key().public_bytes_raw()


def did_from_pub_raw(pub):
    if len(pub) != 32:
        raise ValueError("ed25519 public key must be 32 bytes, got %d" % len(pub))
    return _DID_PREFIX + _b58encode(ED25519_MULTICODEC + pub)


def did_from_priv(priv):
    return did_from_pub_raw(pub_raw(priv))


def pub_raw_from_did(did):
    if not isinstance(did, str) or not did.startswith(_DID_PREFIX):
        raise ValueError("not a did:key:z... string")
    raw = _b58decode(did[len(_DID_PREFIX):])
    if raw[:2] != ED25519_MULTICODEC:
        raise ValueError("did:key is not ed25519-pub multicodec")
    pub = raw[2:]
    if len(pub) != 32:
        raise ValueError("decoded ed25519 key is not 32 bytes")
    return pub


def sign_b64url(priv, message):
    """Sign message (bytes) and return the 86-char unpadded base64url the wire wants."""
    return base64.urlsafe_b64encode(priv.sign(message)).rstrip(b"=").decode("ascii")


def verify_b64url(pub, sig_b64url, message):
    """True iff sig_b64url is a valid Ed25519 signature by pub (32 raw bytes) over
    message. Never raises: a malformed signature or key is a False, not a crash."""
    try:
        pad = "=" * (-len(sig_b64url) % 4)
        sig = base64.urlsafe_b64decode(sig_b64url + pad)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except Exception:
        return False


def verify_by_did(did, sig_b64url, message):
    """verify_b64url resolving the key from the DID string itself."""
    try:
        return verify_b64url(pub_raw_from_did(did), sig_b64url, message)
    except Exception:
        return False


def fingerprint(did):
    """First 16 hex of SHA-256 of the full did:key string, lowercase (patterns.md)."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def note_shard_key(did):
    fp = fingerprint(did)
    return fp[:2], fp[2:]


def did_note_ns(did):
    """The note namespace for this DID: 'did-<shard>'."""
    shard, _ = note_shard_key(did)
    return "did-" + shard
