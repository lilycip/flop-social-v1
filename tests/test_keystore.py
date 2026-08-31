"""Oracle for dashboard/keystore.py. Temp dirs only; never touches a real owner key.
Proves: the key is born local and exportable, decrypts only under the right passphrase,
loads for one signature with nothing cached, imports to recover, and refuses to strand
an existing identity by overwrite. ASCII only, no network.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as diddle  # noqa: E402
import keystore  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


PW = "correct horse battery staple"

d1 = Path(tempfile.mkdtemp(prefix="ks1_"))
ks = keystore.Keystore(d1)
check("no key exists before generate", not ks.exists())
did_str, gen = ks.generate(PW)
check("generate creates a key", ks.exists())
check("generate returns a did:key", did_str.startswith("did:key:z6Mk"))
check("public_did is readable WITHOUT a passphrase", ks.public_did() == did_str)
check("fingerprint is readable without a passphrase", ks.fingerprint() == diddle.fingerprint(did_str))
check("a supplied passphrase is not echoed back", gen is None)

priv = ks.load(PW)
check("load with the right passphrase returns a key", priv is not None)
check("the loaded key matches the stored did", diddle.did_from_priv(priv) == did_str)
check("load with a wrong passphrase returns None", ks.load("nope nope nope one") is None)
check("load with an empty passphrase returns None", ks.load("") is None)
check("load caches nothing (wrong pw still fails after a good load)", ks.load("wrong wrong wrong") is None)

d2 = Path(tempfile.mkdtemp(prefix="ks2_"))
ks2 = keystore.Keystore(d2)
raised = False
try:
    ks2.generate("short")
except keystore.KeyError_:
    raised = True
check("a too-short passphrase is refused", raised and not ks2.exists())
raised = False
try:
    ks.generate(PW)
except keystore.KeyError_:
    raised = True
check("generate refuses to overwrite an existing key", raised)

d3 = Path(tempfile.mkdtemp(prefix="ks3_"))
ks3 = keystore.Keystore(d3)
_, gen3 = ks3.generate(None)
check("generate(None) returns a strong passphrase once", isinstance(gen3, str) and len(gen3) >= 20)
check("the generated passphrase actually unlocks the key", ks3.load(gen3) is not None)

pem = ks.export_pem()
check("export returns PEM bytes", pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
d4 = Path(tempfile.mkdtemp(prefix="ks4_"))
ks4 = keystore.Keystore(d4)
imported_did = ks4.import_pem(pem, PW)
check("import recovers the SAME did on a fresh machine", imported_did == did_str)
check("the imported key loads and signs", diddle.did_from_priv(ks4.load(PW)) == did_str)
d5 = Path(tempfile.mkdtemp(prefix="ks5_"))
ks5 = keystore.Keystore(d5)
raised = False
try:
    ks5.import_pem(pem, "the wrong passphrase entirely")
except keystore.KeyError_:
    raised = True
check("import with the wrong passphrase is refused and writes nothing", raised and not ks5.exists())

d6 = Path(tempfile.mkdtemp(prefix="ks6_"))
ks6 = keystore.Keystore(d6)
ks6.generate(PW)
(d6 / "owner.json").unlink()
check("with the meta gone, exists() reports no usable key", not ks6.exists())
check("but the keystore knows it is STRANDED, not empty", ks6.stranded())
raised = False
try:
    ks6.generate("another good passphrase")
except keystore.KeyError_:
    raised = True
check("generate REFUSES to overwrite a stranded key file", raised and (d6 / "owner.pem").exists())
raised = False
try:
    ks6.import_pem(pem, PW)
except keystore.KeyError_:
    raised = True
check("import REFUSES to overwrite a stranded key file", raised)
d7 = Path(tempfile.mkdtemp(prefix="ks7_"))
ks7 = keystore.Keystore(d7)
ks7.generate(PW)
(d7 / "owner.pem").unlink()
check("a lone meta file is also stranded", ks7.stranded() and not ks7.exists())
raised = False
try:
    ks7.generate(PW)
except keystore.KeyError_:
    raised = True
check("generate refuses over a lone meta file too", raised)

short_pw = "eleven chars"[:11]
d8 = Path(tempfile.mkdtemp(prefix="ks8_"))
ks8 = keystore.Keystore(d8)
ks8.generate(short_pw if False else PW)
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed  # noqa: E402
_p = _Ed.generate()
short_pem = _p.private_bytes(encoding=_ser.Encoding.PEM, format=_ser.PrivateFormat.PKCS8,
                            encryption_algorithm=_ser.BestAvailableEncryption(short_pw.encode()))
d9 = Path(tempfile.mkdtemp(prefix="ks9_"))
ks9 = keystore.Keystore(d9)
msg = ""
try:
    ks9.import_pem(short_pem, short_pw)
except keystore.KeyError_ as e:
    msg = str(e)
check("an under-floor but CORRECT passphrase is refused", not ks9.exists())
check("the refusal says the backup is valid, not that the passphrase is wrong",
      "valid" in msg and "shorter" in msg and "wrong" not in msg.lower())

sig = diddle.sign_b64url(ks.load(PW), b"a steer message")
check("a signature by the loaded key verifies under the public did",
      diddle.verify_by_did(did_str, sig, b"a steer message"))

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
