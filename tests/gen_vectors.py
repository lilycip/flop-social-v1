"""Generate shared/vectors.json: the golden action-string vectors both the Python impl
and the browser's JS port must reproduce byte-for-byte. Run once to freeze; the test
suite then asserts Python still matches it, and the dashboard build asserts JS matches
the same file. Regenerate ONLY on a deliberate format change (bump action.VERSION).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shared import action, steer  # noqa: E402

RH = "a" * 64
RH2 = "b" * 64

CASES = [
    ("ATTEST", {"job_id": "job-abc123", "result_hash": RH}, {"useful": True}),
    ("ATTEST", {"job_id": "job-abc123", "result_hash": RH}, {"useful": False}),
    ("ATTEST", {"job_id": "job-abc123", "result_hash": RH2}, {"useful": True}),
    ("RESULT", {"job_id": "job-abc123", "result": "the delivered answer text"}, None),
    ("CLAIM", {"job_id": "job-abc123"}, None),
    ("NOTE_WRITE", {"namespace": "did-94", "key": "d29ebc4b5d3f8a", "value": "v1.4.0"}, None),
    ("SAY", {"room": "lobby", "text": "hello world"}, None),
]

vectors = []
for verb, target, verdict in CASES:
    vectors.append({
        "verb": verb,
        "target": target,
        "verdict": verdict,
        "action_string": action.action_string(verb, target, verdict),
        "action_commit": action.action_commit(verb, target, verdict),
    })

BIG_NONCE = "9223372036854775807919"[:19]
BIG_EXP = "9999999999"
steer_vectors = []
for verb, target, verdict in [CASES[0], CASES[6]]:
    act = action.action_string(verb, target, verdict)
    for nonce, expiry, channel in [("1", "1000", "mb-p-deadbeef"),
                                   (BIG_NONCE, BIG_EXP, "mb-p-deadbeef")]:
        steer_vectors.append({
            "channel": channel, "nonce": nonce, "expiry": expiry,
            "action_string": act,
            "steer_message": steer.steer_message(channel, act, nonce, expiry).decode("utf-8"),
        })

out = ROOT / "shared" / "vectors.json"
out.write_text(json.dumps(
    {"version": action.VERSION, "vectors": vectors, "steer_vectors": steer_vectors},
    indent=2), encoding="utf-8")
print("wrote %d action vectors and %d steer vectors to %s"
      % (len(vectors), len(steer_vectors), out))
for v in vectors:
    print("  ", v["action_string"])
for s in steer_vectors:
    print("  steer nonce=%s: %s" % (s["nonce"], s["steer_message"]))
