"""Generate the cross-language task-channel parity fixture, agent/vectors/task-python-vector.json.

Regenerate with:  python tests/gen_task_vector.py

It drives the REAL dashboard save_tasks (not a hand-port) against a fake protocol client, captures the
exact note value that would be published, and records {owner_did, secret, note_value, expected}. The TS
test (agent/test/task-read.spec.ts) then feeds note_value to the real gateway readOwnerTasks and asserts
it returns `expected`. Including a MULTIBYTE task exercises the byte/char corner the earlier ASCII-only
fixture missed. `expected` is read back from what save_tasks actually stored, so it can
never drift from the signed bytes.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as D  # noqa: E402
import server as SRV  # noqa: E402


class FakePC:
    def __init__(self):
        self.notes = []

    def set_note(self, namespace, key, value):
        self.notes.append((namespace, key, value))
        return True, "ok"


def main():
    PW = "correct horse battery staple"
    state = Path(tempfile.mkdtemp(prefix="flop-task-vec-"))
    fake = FakePC()
    dash = SRV.Dashboard(str(state), protocol_client=fake)
    dash.ks.generate(PW)
    _, agent_did = D.generate()
    dash.link_agent({"agent_did": agent_did, "nick": "jarvis"})

    tasks = [
        {"id": "presence", "text": "keep a live presence on the board", "schedule": "hourly"},
        {"id": "daily-cjk", "text": "每天在看板上发一条 (post one line daily)", "schedule": "daily"},
        {"id": "hello", "text": "introduce yourself once ✨", "schedule": "once"},
    ]
    code, out = dash.save_tasks({"tasks": tasks, "passphrase": PW})
    assert code == 200 and out["ok"], ("save_tasks failed", code, out)

    ns, key, note_value = fake.notes[-1]
    owner_did = dash.ks.public_did()
    secret = dash._task_secret()
    stored = json.loads((state / "tasks.json").read_text("utf-8"))["tasks"]

    fixture = {"owner_did": owner_did, "secret": secret, "note_value": note_value, "expected": stored}
    outpath = ROOT / "agent" / "vectors" / "task-python-vector.json"
    outpath.write_text(json.dumps(fixture, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.stdout.write("wrote %s (ns=%s key=%s... envelope=%d bytes)\n"
                     % (outpath, ns, key[:10], len(note_value.encode("utf-8"))))


if __name__ == "__main__":
    main()
