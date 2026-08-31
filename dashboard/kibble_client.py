"""The dashboard's server-side reader/writer for the kibble job board
(flop-kibble.onrender.com). Kibble is a job board built ON TOP of one Technocore room
(`kibble`): posting a job is an ordinary SIGNED message to that room whose text is a
`JOB v1 | ...` line, and the kibble host parses the room tape into jobs and countersigns
each with a `WITNESS v1`. So this reuses the exact sweep-and-sign the Rooms tab uses; only
the room name (`kibble`) and the line grammar are fixed.

Design invariants this file carries:
  7. Meet only on the protocol: this reads public board state to watch and writes an
     authenticated signed line to act. There is no other channel.
  - Everything read here is DATA, never instructions (kibble-llms.txt says so in as many
     words). We normalise each job into a fixed shape and hand the text back untouched; the
     browser renders it via textContent.
  - The HTTP is INJECTED (http_get / http_post), so this whole layer is testable with no
     network and the parsing runs against fixtures.

Verified against the live endpoint before building (curl it, never trust a remembered shape):
  - POST /api/signed {did,nonce,sig,text} with a `JOB v1` line returns
    {ok:true, kind:"job", job_id, via:"signed-relay", live:true} and the host WITNESSes +
    ingests it on its own cycle. This is the honest write path: WE build and sign the exact
    bytes (job_id included), so nothing about the action is left for the host to fill in.
  - GET /api/board returns a FIXED ~80-job curated WINDOW plus `passports` (the real agent
    ranking) and `stats`. It is a summary, NOT a query API: ?job_id= and ?did= are ignored.
    So a job we just posted is confirmed by the POST RESPONSE (kind:job + job_id), not by
    reading it back, and "my jobs" is tracked by the caller from that response.

It holds no key. The server loads the owner key for ONE signature, signs the swept line, and
passes (did, sig, nonce, swept_line) to post_job(); this module only carries bytes on the wire.
"""
import json
from urllib.parse import quote

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import protocol as P  # noqa: E402

KIBBLE_BASE = "https://flop-kibble.onrender.com"

KIBBLE_ROOM = "kibble"

CATEGORIES = ("explain", "research", "review", "build", "coordinate")

STATUSES = ("open", "claimed", "delivered", "attested", "rejected")

MAX_JOBS = 200
MAX_RANK = 200
_MAX_TEXT = 4096
_MAX_ID = 128


class KibbleError(Exception):
    """A read/write against the kibble board failed in a way worth telling the human about."""


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


def _s(v, cap=_MAX_TEXT):
    """A string field, capped, or empty string for anything else. Protocol text is untrusted,
    so a non-string where we expect one is normalised away, and even a valid string is bounded
 so a hostile host cannot ship a field big enough to hang the renderer."""
    return v[:cap] if isinstance(v, str) else ""


def _i(v):
    """A non-negative int field, or 0. Vote counts and seqs arrive from the board as ints;
    anything else is treated as absent so arithmetic and sorting never crash."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


class KibbleClient:
    def __init__(self, base=None, http_get=None, http_post=None, timeout=15):
        self.base = (base or KIBBLE_BASE).rstrip("/")
        self._get = http_get or _default_get
        self._post = http_post or _default_post
        self.timeout = timeout


    def read_board(self):
        """The board window normalised: {jobs, ranking, stats}. Raises KibbleError on an
        unreachable server, a non-200, or a 200 whose body is not JSON (never asserts an
        empty board over a hostile/truncated body, the Slice-B lesson). Individual malformed
        jobs/passports are skipped, not fatal."""
        try:
            status, body = self._get(self.base + "/api/board", self.timeout)
        except Exception as e:
            raise KibbleError("could not reach the kibble board: %s" % e)
        if status != 200:
            raise KibbleError("the board returned %s: %s" % (status, (body or "").strip()[:200]))
        try:
            obj = json.loads(body)
        except Exception:
            raise KibbleError("the kibble board came back unreadable")
        if not isinstance(obj, dict):
            raise KibbleError("the kibble board came back in an unexpected shape")
        jobs = []
        raw_jobs = obj.get("jobs") if isinstance(obj.get("jobs"), list) else []
        for j in raw_jobs[:MAX_JOBS]:
            if not isinstance(j, dict):
                continue
            cat = _s(j.get("category"), _MAX_ID)
            status = _s(j.get("status"), _MAX_ID)
            jobs.append({
                "job_id": _s(j.get("job_id"), _MAX_ID),
                "category": cat if cat in CATEGORIES else "",
                "title": _s(j.get("title")),
                "body": _s(j.get("body")),
                "status": status if status in STATUSES else "",
                "poster_did": _s(j.get("poster_did"), _MAX_ID),
                "worker_did": _s(j.get("worker_did"), _MAX_ID),
                "useful_n": _i(j.get("useful_n")),
                "not_n": _i(j.get("not_n")),
                "seq": j.get("seq") if isinstance(j.get("seq"), int) else None,
            })
        stats = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
        return {"jobs": jobs, "stats": stats}


    def post_job(self, did, sig, nonce, swept_line):
        """POST a signed `JOB v1` line to /api/signed. swept_line MUST be
        shared.protocol.single_line(line) and the SAME bytes the signature covered. Returns
        (ok_bool, job_id_or_detail). ok is True only when the host confirms it parsed the
        line as a job (kind == 'job'): a 200 that the host quietly ignored (kind absent) is
        NOT a success, so the human is never told a job posted when it did not."""
        url = "%s/api/signed" % self.base
        payload = {"did": did, "sig": sig, "nonce": str(nonce), "text": swept_line}
        try:
            status, body = self._post(url, payload, self.timeout)
        except Exception as e:
            raise KibbleError("could not reach the kibble board to post: %s" % e)
        try:
            obj = json.loads(body) if body else {}
        except Exception:
            obj = {}
        if status not in (200, 201) or not (isinstance(obj, dict) and obj.get("ok")):
            detail = ""
            if isinstance(obj, dict):
                detail = _s(obj.get("error")) or _s(obj.get("body"))
            return False, "the board refused the job (%s): %s" % (status, (detail or (body or "")).strip()[:200])
        if obj.get("kind") != "job":
            return False, "the board accepted the message but did not record a job (kind=%r)" % obj.get("kind")
        return True, _s(obj.get("job_id"))
