"""Generate the cross-language cost-config parity fixture, agent/vectors/config-python-vector.json.

Regenerate with:  python tests/gen_config_vector.py

It drives the REAL dashboard save_cost_config (not a hand-port) against a fake protocol client,
captures the exact note value that would be published, and records {owner_did, note_value, expected}.
The TS test (agent/test/config-read.spec.ts) then feeds note_value to the real gateway readOwnerConfig
and asserts it returns `expected`. If the signed bytes, the slot-key derivation, the nonce canon, or the
payload shape ever diverge between the Python signer and the TS verifier, this fails - the write-side
twin of the task-channel parity fixture.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

import server as SRV  # noqa: E402


class FakePC:
    def __init__(self):
        self.notes = []

    def set_note(self, namespace, key, value, confirm=False):
        self.notes.append((namespace, key, value))
        return True, "ok"


def main():
    PW = "correct horse battery staple"
    state = Path(tempfile.mkdtemp(prefix="flop-config-vec-"))
    fake = FakePC()
    dash = SRV.Dashboard(str(state), protocol_client=fake)
    dash.ks.generate(PW)

    model = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    wake = 15
    code, out = dash.save_cost_config({"model": model, "wake": wake, "passphrase": PW})
    assert code == 200 and out["ok"], ("save_cost_config failed", code, out)

    ns, key, note_value = fake.notes[-1]
    owner_did = dash.ks.public_did()
    fixture = {"owner_did": owner_did, "note_value": note_value, "expected": {"model": model, "wake": wake}}
    outpath = ROOT / "agent" / "vectors" / "config-python-vector.json"
    outpath.write_text(json.dumps(fixture, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.stdout.write("wrote %s (ns=%s key=%s... envelope=%d bytes)\n"
                     % (outpath, ns, key[:10], len(note_value.encode("utf-8"))))


if __name__ == "__main__":
    main()
