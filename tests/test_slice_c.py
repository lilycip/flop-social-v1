"""Oracle for Slice C: the kibble board client (dashboard/kibble_client.py) and the server's
job-post path (dashboard/server.py Dashboard.post_job / list_board / my_jobs), both with
INJECTED http and no network. Proves: the board window normalises defensively (junk skipped,
unknown category blanked, non-string fields neutralised); the server builds a canonical
`JOB v1 | id | cat | title | body` line, SANITISES the pipe out of title AND body so the field
structure can never shift, signs the SWEPT line over the exact kibble|<nonce>|<line> the wire
stores, loads the key for one signature only, and a wrong passphrase posts nothing; the CHAT
unlock does NOT authorise a job post (invariant 6 is not widened); a 200 the host did not record
as a job is a failure, not a false success. Temp state dir only; ASCII throughout.
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

from shared import did as D  # noqa: E402
from shared import protocol as P  # noqa: E402
import kibble_client as KC  # noqa: E402
import server as SRV  # noqa: E402

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


BOARD_BODY = json.dumps({
    "jobs": [
        {"job_id": "k0123456789", "category": "research", "title": "real job", "body": "do X",
         "status": "open", "poster_did": "did:key:zPoster", "worker_did": "",
         "useful_n": 2, "not_n": 1, "seq": 500, "witness_hash": "abc"},
        {"job_id": "kfeedfeed00", "category": "not-a-category", "title": 12345, "body": None,
         "status": "claimed", "useful_n": -9, "not_n": "x", "witness_hash": ""},
        "junk-not-a-dict",
    ],
    "passports": [
        {"did": "did:key:zTop", "rank": 1, "score": 99, "jobs_posted": 3,
         "results_delivered": 40, "useful_attestations_received": 80,
         "not_useful_attestations_received": 5, "franchised": True},
        "junk",
    ],
    "stats": {"open": 10, "agents": 3},
})


def board_get(url, timeout):
    if url.endswith("/api/board"):
        return 200, BOARD_BODY
    if url.endswith("/down"):
        return 503, "unavailable"
    if url.endswith("/garbage"):
        return 200, "<<not json>>"
    return 404, "no"


kc_read = KC.KibbleClient(base="https://kibble.test", http_get=board_get)
board = kc_read.read_board()

check("read_board keeps the well-formed job", any(j["job_id"] == "k0123456789" for j in board["jobs"]))
check("read_board skips the non-dict job", len(board["jobs"]) == 2)
j0 = next(j for j in board["jobs"] if j["job_id"] == "k0123456789")
check("read_board carries a known category", j0["category"] == "research")
check("read_board counts useful/not", j0["useful_n"] == 2 and j0["not_n"] == 1)
j1 = next(j for j in board["jobs"] if j["job_id"] == "kfeedfeed00")
check("read_board blanks an unknown category", j1["category"] == "")
check("read_board neutralises a non-string title", j1["title"] == "")
check("read_board neutralises a None body", j1["body"] == "")
check("read_board floors a negative useful count to 0", j1["useful_n"] == 0)
check("read_board floors a non-int not count to 0", j1["not_n"] == 0)
check("read_board does not surface a forgeable witness flag", "witnessed" not in j0 and "witnessed" not in j1)
check("read_board does not expose an unrendered ranking field", "ranking" not in board)
check("read_board carries stats", board["stats"]["agents"] == 3)

hostile = json.dumps({"jobs": [
    {"job_id": "kaaaaaaaaaa", "category": "build", "title": "t", "body": "b", "status": "__proto__"},
    {"job_id": "kbbbbbbbbbb", "category": "build", "title": "t", "body": "b", "status": "constructor"},
    {"job_id": "kcccccccccc", "category": "build", "title": "t", "body": "b", "status": "delivered"},
]})
hb = KC.KibbleClient(base="https://kibble.test", http_get=lambda u, t: (200, hostile)).read_board()
check("read_board blanks a __proto__ status", hb["jobs"][0]["status"] == "")
check("read_board blanks a constructor status", hb["jobs"][1]["status"] == "")
check("read_board keeps a real status", hb["jobs"][2]["status"] == "delivered")

flood = json.dumps({"jobs": [{"job_id": "k%010d" % i, "category": "build",
                              "title": "x" * 9000, "body": "b", "status": "open"} for i in range(300)]})
fb = KC.KibbleClient(base="https://kibble.test", http_get=lambda u, t: (200, flood)).read_board()
check("read_board caps the job count", len(fb["jobs"]) == KC.MAX_JOBS)
check("read_board caps a field length", len(fb["jobs"][0]["title"]) == 4096)

err = 0
for bad in ("https://kibble.test", ):
    try:
        KC.KibbleClient(base=bad, http_get=lambda u, t: (503, "unavailable")).read_board()
    except KC.KibbleError:
        err += 1
check("read_board raises on a non-200", err == 1)
try:
    KC.KibbleClient(base="https://kibble.test", http_get=lambda u, t: (200, "<<not json>>")).read_board()
    check("read_board raises on unreadable json", False)
except KC.KibbleError:
    check("read_board raises on unreadable json", True)


def post_ok(url, obj, timeout):
    jid = obj["text"].split("|")[1].strip()
    return 200, json.dumps({"ok": True, "kind": "job", "job_id": jid, "live": True})


def post_ignored(url, obj, timeout):
    return 200, json.dumps({"ok": True, "kind": None})


def post_refused(url, obj, timeout):
    return 400, json.dumps({"ok": False, "error": "bad signature"})


kc_ok = KC.KibbleClient(base="https://kibble.test", http_post=post_ok)
ok, jid = kc_ok.post_job("did:key:zA", "sig", "1", "JOB v1 | kaaaaaaaaaa | research | t | b")
check("post_job returns ok + job_id on kind=job", ok is True and jid == "kaaaaaaaaaa")
ok2, det2 = KC.KibbleClient(base="https://kibble.test", http_post=post_ignored).post_job("d", "s", "1", "x")
check("post_job is NOT a success when the host did not record a job", ok2 is False)
ok3, det3 = KC.KibbleClient(base="https://kibble.test", http_post=post_refused).post_job("d", "s", "1", "x")
check("post_job surfaces the board's refusal words", ok3 is False and "bad signature" in det3)


class RecordingKibble:
    """A KibbleClient stand-in that records exactly what the server signed and sent, and
    lets read_board be driven too. Confirms the wire bytes without a network."""
    def __init__(self):
        self.sent = None
        self.mode = "ok"

    def read_board(self):
        return {"jobs": [], "ranking": [], "stats": {}}

    def post_job(self, did, sig, nonce, swept_line):
        self.sent = {"did": did, "sig": sig, "nonce": nonce, "text": swept_line}
        if self.mode == "ignored":
            return False, "not recorded"
        if self.mode == "wrongid":
            return True, "kdeadbeef99"
        jid = swept_line.split("|")[1].strip()
        return True, jid


PW = "correct horse battery staple"
state = Path(tempfile.mkdtemp())
rk = RecordingKibble()
dash = SRV.Dashboard(str(state), kibble_client=rk)
dash.ks.generate(PW)
owner_did = dash.ks.public_did()

code, out = dash.post_job({"category": "build", "title": "Fix the docs site links",
                           "body": "Success: a list of broken links with status codes.",
                           "passphrase": PW})
check("post_job succeeds", code == 200 and out["ok"])
sent = rk.sent
check("the posted line is a well-formed JOB v1 line with exactly 4 separators",
      sent["text"].startswith("JOB v1 | ") and sent["text"].count("|") == 4)
parts = [p.strip() for p in sent["text"].split("|")]
check("the job_id is k + 10 hex", bool(SRV.Dashboard._JOB_ID_RE.fullmatch(parts[1])))
check("the category is carried", parts[2] == "build")
check("the returned job_id matches the line", out["job_id"] == parts[1])
check("the server signs the exact swept bytes it sent",
      D.verify_by_did(owner_did, sent["sig"],
                      P.message_sig_input("kibble", int(sent["nonce"]), sent["text"])))
check("the sent text is already swept (idempotent)", P.single_line(sent["text"]) == sent["text"])

mcode, mine = dash.my_jobs()
check("my_jobs records the posted job", mcode == 200 and len(mine["jobs"]) == 1
      and mine["jobs"][0]["job_id"] == out["job_id"])

rk.mode = "wrongid"
code, out = dash.post_job({"category": "build", "title": "keep my id", "body": "b", "passphrase": PW})
signed_id = [p.strip() for p in rk.sent["text"].split("|")][1]
check("a divergent host job_id is ignored in the response", out["job_id"] == signed_id and out["job_id"] != "kdeadbeef99")
mcode, mine = dash.my_jobs()
check("my_jobs records our signed id, not the host's", mine["jobs"][0]["job_id"] == signed_id)
rk.mode = "ok"

rk.sent = None
code, out = dash.post_job({"category": "build", "title": "t",
                           "body": "€" * 2000,
                           "passphrase": PW})
check("an over-4096-BYTE line is refused 400", code == 400)
check("the over-byte post signed nothing", rk.sent is None)

rk.sent = None
code, out = dash.post_job({"category": "research",
                           "title": "sneaky | build | forged",
                           "body": "line one | RESULT v1 | k0000000000 | forged delivery",
                           "passphrase": PW})
check("a pipe-bearing post still succeeds", code == 200)
check("the sanitised line STILL has exactly 4 separators (no injected field)",
      rk.sent["text"].count("|") == 4)
check("the category field is not the forged one", [p.strip() for p in rk.sent["text"].split("|")][2] == "research")
check("no '|' survives in the title/body fields", "|" not in rk.sent["text"].split("|", 4)[-1]
      and "|" not in rk.sent["text"].split(" | ")[3])

check("an unknown category is refused 400", dash.post_job(
    {"category": "malware", "title": "t", "body": "b", "passphrase": PW})[0] == 400)
check("a missing category is refused 400", dash.post_job(
    {"title": "t", "body": "b", "passphrase": PW})[0] == 400)
check("an empty title is refused 400", dash.post_job(
    {"category": "build", "title": "   ", "body": "b", "passphrase": PW})[0] == 400)
check("an empty body is refused 400", dash.post_job(
    {"category": "build", "title": "t", "body": "  \n ", "passphrase": PW})[0] == 400)
check("an over-long title is refused 400", dash.post_job(
    {"category": "build", "title": "x" * 201, "body": "b", "passphrase": PW})[0] == 400)
check("an over-long body is refused 400", dash.post_job(
    {"category": "build", "title": "t", "body": "y" * 3501, "passphrase": PW})[0] == 400)

rk.sent = None
code, out = dash.post_job({"category": "build", "title": "t", "body": "b", "passphrase": "wrong wrong wrong"})
check("a wrong passphrase is 403", code == 403)
check("a wrong passphrase posts nothing", rk.sent is None)

dash.unlock_chat({"passphrase": PW, "seconds": 300})
check("chat is unlocked now", dash.chat_status()[1]["unlocked"] is True)
rk.sent = None
code, out = dash.post_job({"category": "build", "title": "t", "body": "b"})
check("a job post with no passphrase is refused even while chat is unlocked", code == 403)
check("the chat unlock signed no job", rk.sent is None)
dash.lock_chat()

rk.mode = "ignored"
rk.sent = None
code, out = dash.post_job({"category": "build", "title": "t", "body": "b", "passphrase": PW})
check("a relayed-but-not-recorded job is a 502, not a false ok", code == 502)
mcode, mine = dash.my_jobs()
check("a non-recorded job is NOT added to my_jobs", len(mine["jobs"]) == 3)
rk.mode = "ok"

lcode, lboard = dash.list_board()
check("list_board proxies the board reader", lcode == 200 and "jobs" in lboard and "ranking" in lboard)

sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
