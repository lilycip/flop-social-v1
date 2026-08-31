"""The human OWNER key, on the human's own machine. Born local, encrypted at rest,
exportable so the person can back it up, importable to recover or add a device, and
loaded only long enough for ONE signature.

Design invariants this file carries:
  - Two identities: this is the HUMAN OWNER key. It authorizes; it owns nothing on the
    protocol. Only its public did:key ever leaves the machine.
  - Local, we host nothing: the private key is a PKCS8 PEM encrypted under the person's
    passphrase, sitting in a file they control. Export hands them that exact encrypted
    PEM to store somewhere safe; import brings it back.
  - Passphrase per approval, NO ambient unlock: load(passphrase) returns a key for one
    signature and the caller drops it. Nothing here caches a decrypted key. A process
    that cannot supply the passphrase cannot sign, an injected agent included.
  - Scope line: we are a dashboard, not an antivirus. If the person's machine is fully
    compromised the encrypted PEM plus a keylogged passphrase is theirs to lose. What we
    guarantee is that the key is never held decrypted at rest and never leaves in the clear.

The public did:key and its fingerprint live in a small plaintext meta file next to the
encrypted key, so the dashboard can show the identity and filter the protocol to the
agent without ever unlocking the private key.
"""
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import did as diddle  # noqa: E402

PASSPHRASE_FLOOR = 12


class KeyError_(Exception):
    """A keystore operation the caller should surface to the human, with a plain reason."""


class Keystore:
    """Wraps the two files: <dir>/owner.pem (encrypted private) and <dir>/owner.json
    (public did + fingerprint, plaintext)."""

    def __init__(self, directory):
        self.dir = Path(directory)
        self.key_path = self.dir / "owner.pem"
        self.meta_path = self.dir / "owner.json"


    def exists(self):
        return self.key_path.exists() and self.meta_path.exists()

    def _occupied(self):
        """True if EITHER file is present. generate/import refuse on this, not on exists():
        a lone owner.pem (its meta lost to a delete, an AV quarantine, a sync, or a crash
        between the two writes in _write) reads as 'no key' to exists(), and overwriting it
        would silently destroy the real identity the no-overwrite guard exists to protect.
        Absence of the meta is not absence of the key."""
        return self.key_path.exists() or self.meta_path.exists()

    def stranded(self):
        """A key file with no readable meta (or the reverse): present but not usable, and
        NOT safe to overwrite. The dashboard shows this instead of a clean first-run."""
        return self._occupied() and not self.exists()

    def public_did(self):
        """The human's did:key, readable without unlocking. None if no key yet."""
        if not self.meta_path.exists():
            return None
        try:
            return json.loads(self.meta_path.read_text("utf-8")).get("did")
        except Exception:
            return None

    def fingerprint(self):
        d = self.public_did()
        return diddle.fingerprint(d) if d else None


    def generate(self, passphrase=None):
        """Create a NEW owner key. Refuses to overwrite an existing one (that would strand
        the old identity). If passphrase is None a strong one is generated and returned
        ONCE; otherwise the given passphrase must clear the floor. Returns (did, passphrase)
        where passphrase is echoed only when generated, else None."""
        if self._occupied():
            raise KeyError_("an owner key already exists here; refusing to overwrite it. "
                            "Export and move it, or point at an empty folder.")
        generated = None
        if passphrase is None:
            passphrase = secrets.token_urlsafe(18)
            generated = passphrase
        self._check_passphrase(passphrase)
        priv = Ed25519PrivateKey.generate()
        self._write(priv, passphrase)
        return self.public_did(), generated

    def import_pem(self, pem_bytes, passphrase):
        """Bring an existing owner key onto this machine (recover, or add a device).
        Verifies the PEM decrypts under the passphrase and is Ed25519 BEFORE writing.
        Refuses to overwrite an existing key. Returns the did."""
        if self._occupied():
            raise KeyError_("an owner key already exists here; refusing to overwrite it.")
        priv = self._load_pem(pem_bytes, passphrase)
        if priv is None:
            raise KeyError_("could not decrypt that key with that passphrase, or it is "
                            "not an Ed25519 owner key.")
        if len(passphrase) < PASSPHRASE_FLOOR:
            raise KeyError_("that backup is valid and the passphrase is correct, but it is "
                            "shorter than this version allows (at least %d characters). "
                            "Re-encrypt your backup under a longer passphrase, then import."
                            % PASSPHRASE_FLOOR)
        self._write(priv, passphrase)
        return self.public_did()

    def export_pem(self):
        """The encrypted PEM bytes to hand the person for backup. Still encrypted under
        their passphrase; safe to store as long as the passphrase is not beside it."""
        if not self.key_path.exists():
            raise KeyError_("no owner key to export yet.")
        return self.key_path.read_bytes()


    def load(self, passphrase):
        """Return the Ed25519 private key for ONE signature, or None if the passphrase is
        empty/wrong or the stored key is not Ed25519. The caller signs and drops it; this
        method caches nothing."""
        if not passphrase or not self.key_path.exists():
            return None
        return self._load_pem(self.key_path.read_bytes(), passphrase)


    def _check_passphrase(self, passphrase):
        if not isinstance(passphrase, str) or len(passphrase) < PASSPHRASE_FLOOR:
            raise KeyError_("passphrase must be at least %d characters." % PASSPHRASE_FLOOR)

    def _write(self, priv, passphrase):
        self._check_passphrase(passphrase)
        self.dir.mkdir(parents=True, exist_ok=True)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        d = diddle.did_from_priv(priv)
        self.key_path.write_bytes(pem)
        self.meta_path.write_text(json.dumps({
            "did": d,
            "fingerprint": diddle.fingerprint(d),
            "pub_hex": diddle.pub_raw(priv).hex(),
        }, indent=2), "utf-8")

    def _load_pem(self, pem_bytes, passphrase):
        try:
            priv = serialization.load_pem_private_key(
                pem_bytes, password=passphrase.encode("utf-8"))
        except Exception:
            return None
        if not isinstance(priv, Ed25519PrivateKey):
            return None
        return priv
