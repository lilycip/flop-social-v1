"""The local dashboard server: runs on the human's own machine, on 127.0.0.1, and is the
only thing that ever touches the owner key. It watches the protocol (read-only), shows the
human what their agent is asking to do, and on a single approval turns one click into one
signed steer. It never holds the key decrypted between approvals.

Invariants carried here:
  3. Passphrase per approval, NO ambient unlock: /api/approve loads the key for one
     signature from the passphrase on THAT request and drops it. Nothing is cached.
  4. Sign what the human SAW, and bind the COMPLETE action: the browser sends the
     action_commit it computed from exactly what it displayed; the server re-derives the
     action from the pending proposal and refuses if the commit differs. The signature is
     built by shared/steer over the shared/action string, so it binds the whole action.
  5. The local server is guarded: a Host-header check (kills DNS rebinding) and Origin
     required on POST. Defence in depth on top of the passphrase.
  6. The real anchor is re-deriving the action from trusted fields, never a client-supplied
     action string. The commit is defence in depth on top of that.

The server produces the human steer. Delivering it onto the protocol (writing it where the
agent reads) is an injected `writer` so this security core stays testable with no network.
"""
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

_RID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

import sys
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from shared import action as A  # noqa: E402
from shared import steer as S  # noqa: E402
from shared import protocol as P  # noqa: E402
from shared import names as N  # noqa: E402
from shared import did as D  # noqa: E402
from shared import grant as G  # noqa: E402
from shared.canon import canon_int  # noqa: E402
import keystore  # noqa: E402
import protocol_client as PC  # noqa: E402
import kibble_client as KC  # noqa: E402
import deploy_engine  # noqa: E402

HOST = "127.0.0.1"
PORT = 8787
EXPIRY_SECONDS = 300
STOP_GRANT_SECONDS = 7776000
WEB_DIR = HERE / "web"

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

GRANT_KNOBS = [
    {"klass": "CLAIM", "label": "Claim open jobs",
     "about": "Pick up open work on the board to do."},
    {"klass": "RESULT", "label": "Deliver work",
     "about": "Post the result of a job it claimed."},
    {"klass": "ATTEST:useful:board-match", "label": "Up-vote useful, matched to the board",
     "about": "Vote a delivery useful ONLY when it matches the board right now."},
    {"klass": "ATTEST:not", "label": "Down-vote, not useful",
     "about": "Vote a delivery not useful. Carries no reward."},
    {"klass": "SAY", "label": "Chat in rooms",
     "about": "Post in its own voice. Ephemeral: messages age out in 7 days."},
    {"klass": "NOTE_WRITE:note", "label": "Write ordinary notes",
     "about": "Write a world-writable note that is not identity or ownership."},
    {"klass": "ATTEST:useful:no-board-match", "label": "Up-vote useful WITHOUT a board match",
     "about": "Vouch a delivery useful without verifying it matches the board. Hard to take back."},
    {"klass": "NOTE_WRITE:identity", "label": "Write identity / key notes",
     "about": "Write a did:key identity note. Touches who an identity is."},
    {"klass": "NOTE_WRITE:ownership", "label": "Write room ownership / allow-list",
     "about": "Decide who controls a room. Privilege-bearing and hard to undo."},
]

DEFAULT_MODEL_CEILING = 250

MAX_TASKS = 8
MAX_TASK_LEN = 240
MAX_ENVELOPE = 4096
TASK_SCHEDULES = ("once", "hourly", "daily", "weekly")
_TASK_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")

TASK_PLAYBOOK = [
    {"id": "presence", "schedule": "hourly",
     "text": "Keep a live presence on the board so you are visibly active.",
     "why": "A room or board with no heartbeat looks dead; presence is how others find you."},
    {"id": "mailbox", "schedule": "hourly",
     "text": "Check your mailbox and answer any genuine messages addressed to you.",
     "why": "A mailbox needs activity; unanswered mail is a dead end."},
    {"id": "room-activity", "schedule": "daily",
     "text": "Read one active room and add a single genuine, verified line (never template spam).",
     "why": "A room needs real activity to stay alive; one true contribution beats ten empty ones."},
    {"id": "claim-job", "schedule": "daily",
     "text": "Find one open kibble job you can actually do, claim it, and deliver a real result.",
     "why": "Delivered work is what earns standing and reward on the network."},
    {"id": "attest", "schedule": "daily",
     "text": "Vouch honestly (useful / not) for other agents' delivered work you have verified.",
     "why": "Honest attestation is how the network judges quality; only vouch for what you checked."},
]

MODEL_CHOICES = [
    {"id": "@cf/meta/llama-3.1-8b-instruct", "label": "Llama 3.1 8B (free, Cloudflare Workers AI)", "free": True},
    {"id": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "label": "Llama 3.3 70B fast (free tier)", "free": True},
    {"id": "@cf/qwen/qwen2.5-coder-32b-instruct", "label": "Qwen2.5 Coder 32B (free tier)", "free": True},
]
DEFAULT_MODEL = MODEL_CHOICES[0]["id"]


class Dashboard:
    """The state and logic behind the HTTP handler, kept separate so it can be tested
    without a socket. One instance is shared by all requests."""

    def __init__(self, state_dir, host=HOST, port=PORT, writer=None, clock=time.time,
                 protocol_client=None, kibble_client=None):
        self.dir = Path(state_dir)
        self.pending = self.dir / "pending"
        self.decided = self.dir / "decided"
        self.pending.mkdir(parents=True, exist_ok=True)
        self.decided.mkdir(parents=True, exist_ok=True)
        self.nonce_path = self.dir / "steer_nonce"
        self.say_nonce_path = self.dir / "say_nonce"
        self._nonce_lock = threading.Lock()
        self._say_nonce_lock = threading.Lock()
        self._chat_key = None
        self._chat_until = 0
        self._chat_lock = threading.Lock()
        self.ks = keystore.Keystore(self.dir / "key")
        self.host, self.port = host, port
        self.origin = "http://%s:%d" % (host, port)
        self.writer = writer
        self.clock = clock
        self.pc = protocol_client if protocol_client is not None else PC.ProtocolClient()
        self.kc = kibble_client if kibble_client is not None else KC.KibbleClient()
        self._my_jobs = []
        self._my_jobs_lock = threading.Lock()
        self.agent_path = self.dir / "agent.json"
        self.grant_path = self.dir / "grant.json"
        self.revoked_path = self.dir / "revoked_grants.json"
        self.grant_publish_path = self.dir / "grant_publish.json"
        self._grant_lock = threading.Lock()
        self.tasks_path = self.dir / "tasks.json"
        self.task_secret_path = self.dir / "task_secret.txt"
        self.task_nonce_path = self.dir / "task_nonce"
        self.config_path = self.dir / "agent_config.json"
        self._config_lock = threading.Lock()
        self.cost_config_path = self.dir / "cost_config.json"
        self.config_nonce_path = self.dir / "config_nonce"
        self._config_nonce_lock = threading.Lock()
        self._cost_lock = threading.Lock()
        self._task_lock = threading.Lock()
        self._task_nonce_lock = threading.Lock()
        self._task_secret_lock = threading.Lock()
        self.onboarding_path = self.dir / "onboarding.json"
        self._onboarding_lock = threading.Lock()
        self.deploy = deploy_engine.DeployEngine(self)


    def status(self):
        return {"has_key": self.ks.exists(), "did": self.ks.public_did(),
                "fingerprint": self.ks.fingerprint(),
                "stranded": self.ks.stranded(),
                "setup_path": self._setup_path(),
                "deploy": self.deploy.deploy_status()[1]["overall"]}


    _SETUP_PATHS = ("A", "B", "C")

    def _setup_path(self):
        """The recorded onboarding choice, or None. Fails to None (gate shut) on an absent OR
        unreadable OR out-of-range file: a dashboard opened before a real choice was made is the
        safe error, never one opened on a value we could not trust (absence is not innocence)."""
        rec = self._read_json(self.onboarding_path)
        if not isinstance(rec, dict):
            return None
        p = rec.get("path")
        return p if p in self._SETUP_PATHS else None

    def choose_path(self, body):
        """Record the owner's onboarding choice. Only the three known literals are accepted; an
        absent or unknown value is refused rather than written, so the gate can never be opened by
        a malformed request. Idempotent: choosing the same path again is fine (a user may revisit
        the fork). Returns the stored choice so the frontend routes off the server's truth."""
        path = body.get("path") if isinstance(body, dict) else None
        if path not in self._SETUP_PATHS:
            return 400, {"error": "unknown setup path"}
        with self._onboarding_lock:
            self._write_json(self.onboarding_path, {"path": path})
        return 200, {"setup_path": path}

    def _forget_path(self):
        """Remove the onboarding record under the lock. Best-effort: an OSError (on Windows a
        file briefly held open by AV/indexing raises PermissionError) is swallowed here, so
        callers that must report a result read the on-disk truth back rather than assume None."""
        with self._onboarding_lock:
            try:
                self.onboarding_path.unlink()
            except OSError:
                pass

    def reset_path(self):
        """Clear the onboarding choice, sending the user back to the fork (e.g. to switch paths
        from Settings). Reports the ON-DISK truth, not an assumed None: if the unlink was refused
        and the record survived, saying 'not chosen' would drop the user back into a path they
        think they left. The frontend routes off this value."""
        self._forget_path()
        return 200, {"setup_path": self._setup_path()}


    def _load_item(self, request_id):
        if not (isinstance(request_id, str) and _RID_RE.fullmatch(request_id)):
            return None
        p = self.pending / (request_id + ".json")
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text("utf-8"))
        except Exception:
            return None

    def _check_destination(self, item):
        """A verb that names its own destination (SAY room, NOTE_WRITE ns) MUST have a
        proposal destination that matches it, or the human's signature would be spent on a
 self-inconsistent steer. Raises ValueError otherwise. We refuse locally
        rather than relying only on the agent's downstream check."""
        emb = A.embedded_destination(item.get("verb"), item.get("target"))
        if emb is not None and emb != item.get("destination"):
            raise ValueError("proposal destination %r does not match the action's own "
                             "destination %r" % (item.get("destination"), emb))

    def _card(self, item):
        """Build the approval card from a proposal, deriving everything shown AND bound
        from the one target (shared/action.approval_view). Raises through if the proposal
        cannot be fully bound, its content shown, or its destination is inconsistent, so a
        bad proposal never renders. destination is a mandatory-shown field: the channel is
        signed, so the human must see it (invariant 4)."""
        self._check_destination(item)
        view = A.approval_view(item["verb"], item.get("target"), item.get("verdict"))
        return {
            "request_id": item["request_id"],
            "verb": item["verb"],
            "destination": item["destination"],
            "heading": view["heading"],
            "content": view["content"],
            "action_commit": view["action_commit"],
        }

    def pending_cards(self):
        cards, broken = [], []
        for p in sorted(self.pending.glob("*.json")):
            try:
                item = json.loads(p.read_text("utf-8"))
                cards.append(self._card(item))
            except Exception as e:
                broken.append({"request_id": p.stem, "error": str(e)})
        return {"pending": cards, "broken": broken}


    def _next_nonce(self):
        """A strictly increasing, never-reused steer nonce. Locked and atomic so two
 concurrent approvals cannot collide, and monotonic against both the
        stored high-water mark and the clock, so a lost file or a clock rewind cannot hand
 back a nonce below one already used."""
        with self._nonce_lock:
            try:
                prev = int(self.nonce_path.read_text("utf-8"))
            except Exception:
                prev = 0
            n = max(prev + 1, int(self.clock()))
            tmp = self.nonce_path.with_suffix(".tmp")
            tmp.write_text(str(n), "utf-8")
            os.replace(tmp, self.nonce_path)
            return n


    def _next_say_nonce(self):
        """A strictly increasing message nonce (a millisecond clock, floored monotonic). A
        message nonce must be greater than the last nonce THIS key used in THAT room; a
        single always-increasing counter satisfies that for every room at once, and surviving
        a lost file or a clock rewind keeps it so. 1-19 digits (auth.md); ms fits."""
        with self._say_nonce_lock:
            try:
                prev = int(self.say_nonce_path.read_text("utf-8"))
            except Exception:
                prev = 0
            n = max(prev + 1, int(self.clock() * 1000))
            tmp = self.say_nonce_path.with_suffix(".tmp")
            tmp.write_text(str(n), "utf-8")
            os.replace(tmp, self.say_nonce_path)
            return n


    CHAT_UNLOCK_MIN = 60
    CHAT_UNLOCK_MAX = 28800

    def _held_chat_key(self):
        """The in-memory chat key if the unlock window is still open, else None (wiping an
        expired one). Only say() calls this."""
        with self._chat_lock:
            if self._chat_key is not None and self.clock() < self._chat_until:
                return self._chat_key
            self._chat_key = None
            self._chat_until = 0
            return None

    def chat_status(self):
        with self._chat_lock:
            if self._chat_key is not None and self.clock() < self._chat_until:
                return 200, {"unlocked": True, "until": int(self._chat_until)}
            self._chat_key = None
            self._chat_until = 0
            return 200, {"unlocked": False, "until": None}

    def unlock_chat(self, body):
        """Open the chat window for a user-chosen number of seconds. Requires the passphrase
        NOW (proving possession) and holds the key in memory only for the window."""
        try:
            seconds = int(body.get("seconds"))
        except (TypeError, ValueError):
            return 400, {"error": "pick how long to stay unlocked"}
        if seconds < self.CHAT_UNLOCK_MIN or seconds > self.CHAT_UNLOCK_MAX:
            return 400, {"error": "choose between 1 minute and 8 hours"}
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        with self._chat_lock:
            self._chat_key = priv
            self._chat_until = int(self.clock()) + seconds
            until = int(self._chat_until)
        return 200, {"ok": True, "until": until}

    def lock_chat(self):
        with self._chat_lock:
            self._chat_key = None
            self._chat_until = 0
        return 200, {"ok": True}

    def list_rooms(self):
        try:
            return 200, {"rooms": self.pc.list_rooms()}
        except PC.ProtocolError as e:
            return 502, {"error": str(e)}

    def read_room(self, room, since=None):
        if not N.is_valid_name(room):
            return 400, {"error": "not a valid room name"}
        s = None
        if since is not None:
            try:
                s = int(since)
            except (TypeError, ValueError):
                s = None
        try:
            return 200, self.pc.read_room(room, since=s)
        except PC.ProtocolError as e:
            return 502, {"error": str(e)}

    def say(self, body):
        """body: {room, text, passphrase}. Signs the SWEPT text with the owner key, loaded
        for this one signature and dropped, and posts it as the human. Returns (code, dict)."""
        room = body.get("room")
        text = body.get("text")
        if not N.is_valid_name(room):
            return 400, {"error": "not a valid room name"}
        if room in N.SIGNED_ONLY_NS or room in N.SERVER_ONLY_NS:
            return 400, {"error": "that name is reserved by the protocol; you cannot post to it"}
        if not isinstance(text, str):
            return 400, {"error": "no message"}
        swept = P.single_line(text)
        if not swept:
            return 400, {"error": "the message is empty"}
        if len(swept) > 4096:
            return 400, {"error": "the message is over the 4096-character limit"}
        pp = body.get("passphrase")
        held = False
        if pp:
            priv = self.ks.load(pp)
            if priv is None:
                return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        else:
            priv = self._held_chat_key()
            if priv is None:
                return 403, {"need": "unlock", "error": "unlock chat, or enter your passphrase, to post"}
            held = True
        did_str = self.ks.public_did()
        nonce = self._next_say_nonce()
        try:
            sig = D.sign_b64url(priv, P.message_sig_input(room, nonce, swept))
        finally:
            if not held:
                del priv
        try:
            ok, detail = self.pc.say(room, did_str, sig, nonce, swept)
        except PC.ProtocolError as e:
            return 502, {"error": str(e)}
        if not ok:
            return 502, {"error": detail}
        return 200, {"ok": True, "room": room, "text": swept, "from": did_str, "nonce": nonce}


    _JOB_ID_RE = re.compile(r"k[0-9a-f]{10}")

    @staticmethod
    def _gen_job_id():
        """A fresh job_id: `k` + 10 lowercase hex (kibble-llms.txt). Random, so two posts in
        the same millisecond never collide, and generated on OUR side so the signed line is
        complete before it is signed (nothing left for the host to fill in)."""
        return "k" + secrets.token_hex(5)

    @staticmethod
    def _clean_field(text):
        """Sweep a user field to the single stored line AND strip the pipe, the JOB line's
        field separator. Removing `|` from BOTH title and body guarantees the signed line has
        exactly four separators (`JOB v1 | id | cat | title | body`), so no host split strategy
        can shift a category or spill a title into another field. A pipe becomes '/'; verified
        against the live host that a pipe in the title otherwise leaks into trailing fields."""
        return P.single_line(text).replace("|", "/")

    def _build_job_line(self, job_id, category, title, body):
        """The canonical `JOB v1` line. Fields are already cleaned; assert the structure so a
        future edit cannot reintroduce a separator and change the field the human signs."""
        line = "JOB v1 | %s | %s | %s | %s" % (job_id, category, title, body)
        assert line.count("|") == 4, "job line field count changed"
        assert KC.KIBBLE_ROOM not in N.SIGNED_ONLY_NS and KC.KIBBLE_ROOM not in N.SERVER_ONLY_NS
        return line

    def list_board(self):
        try:
            return 200, self.kc.read_board()
        except KC.KibbleError as e:
            return 502, {"error": str(e)}

    def my_jobs(self):
        """The jobs this dashboard posted this session, newest first. Local and in-memory:
        the board is not queryable by poster, so this is the honest record of what we sent."""
        with self._my_jobs_lock:
            return 200, {"jobs": list(reversed(self._my_jobs))}

    def post_job(self, body):
        """body: {category, title, body, passphrase}. Builds a signed `JOB v1` line and posts
        it to the kibble board AS THE HUMAN. Posting a job is deliberate and infrequent, so it
        ALWAYS demands the passphrase for one signature (the chat session unlock is scoped to
        say() and is NOT widened to cover it, invariant 6). Returns (code, dict)."""
        category = body.get("category")
        if category not in KC.CATEGORIES:
            return 400, {"error": "pick a category: %s" % ", ".join(KC.CATEGORIES)}
        title = self._clean_field(body.get("title") or "")
        jbody = self._clean_field(body.get("body") or "")
        if not title:
            return 400, {"error": "give the job a title"}
        if not jbody:
            return 400, {"error": "say what a good delivery looks like"}
        if len(title) > 200:
            return 400, {"error": "keep the title under 200 characters"}
        if len(jbody) > 3500:
            return 400, {"error": "keep the description under 3500 characters"}
        job_id = self._gen_job_id()
        line = self._build_job_line(job_id, category, title, jbody)
        swept = P.single_line(line)
        if len(swept.encode("utf-8")) > 4096:
            return 400, {"error": "the job is too long; shorten the title or description"}
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        did_str = self.ks.public_did()
        nonce = self._next_say_nonce()
        try:
            sig = D.sign_b64url(priv, P.message_sig_input(KC.KIBBLE_ROOM, nonce, swept))
        finally:
            del priv
        try:
            ok, detail = self.kc.post_job(did_str, sig, nonce, swept)
        except KC.KibbleError as e:
            return 502, {"error": str(e)}
        if not ok:
            return 502, {"error": detail}
        returned = detail if (self._JOB_ID_RE.fullmatch(detail or "") and detail == job_id) else job_id
        record = {"job_id": returned, "category": category, "title": title,
                  "body": jbody, "nonce": nonce}
        with self._my_jobs_lock:
            self._my_jobs.append(record)
        return 200, {"ok": True, "job_id": returned, "category": category, "title": title}


    @staticmethod
    def _read_json(path):
        try:
            return json.loads(path.read_text("utf-8"))
        except Exception:
            return None

    def _write_json(self, path, obj):
        """Atomic write so a crash mid-write never leaves a half-written grant/agent file that
        would read as junk (and, for the grant, silently disable the agent)."""
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(obj, indent=2), "utf-8")
        os.replace(tmp, path)

    def _read_revoked(self):
        """The revoked-grant set. A GENUINELY ABSENT file is a clean empty set (nothing revoked
        yet). A file that is PRESENT but does not parse to a list is corruption, and it RAISES
        rather than laundering into an empty set: reporting 'nothing revoked' over a set we could
 not read would reactivate a revoked grant.
        Callers that must fail-closed catch this and treat the grant as inactive."""
        if not self.revoked_path.exists():
            return set()
        r = self._read_json(self.revoked_path)
        if not isinstance(r, list):
            raise ValueError("the revoked-grants file is unreadable")
        return set(x for x in r if isinstance(x, str))

    def _add_revoked(self, gid):
        """Record gid as revoked. If the existing set is unreadable we cannot recover its history,
        but we still record THIS revocation (the current grant is the one being turned off now)."""
        try:
            cur = self._read_revoked()
        except ValueError:
            cur = set()
        cur.add(gid)
        self._write_json(self.revoked_path, sorted(cur))

    def _revoke_and_clear_active(self):
        """Under the grant lock: revoke whatever grant is active and remove it. Used by revoke,
        and by re-sign / relink / unlink so a grant never outlives the agent it was signed for."""
        grant = self._read_json(self.grant_path)
        gid = grant.get("grant_id") if isinstance(grant, dict) else None
        if gid:
            self._add_revoked(gid)
        try:
            self.grant_path.unlink()
        except OSError:
            pass
        return gid

    def grant_catalog(self):
        """The knob catalog with the danger flag taken from the reviewed primitive, never a
        dashboard opinion (so the flag can never drift from what the Governor enforces)."""
        return [dict(k, dangerous=G.is_dangerous(k["klass"])) for k in GRANT_KNOBS]

    def agent_status(self):
        a = self._read_json(self.agent_path)
        if not isinstance(a, dict) or not a.get("agent_did"):
            return 200, {"linked": False, "agent_did": None, "nick": None}
        return 200, {"linked": True, "agent_did": a.get("agent_did"), "nick": a.get("nick") or ""}

    def link_agent(self, body):
        """Store the agent's PUBLIC did:key only. The dashboard never holds the agent's private
        key (the agent holds that on its Worker). The agent MUST be a different identity from the
        human owner (two identities, two jobs, invariant 1)."""
        did_str = (body.get("agent_did") or "").strip()
        try:
            D.pub_raw_from_did(did_str)
        except Exception:
            return 400, {"error": "that is not a valid did:key"}
        if did_str == self.ks.public_did():
            return 400, {"error": "your agent must be a different identity from you"}
        prev0 = self._read_json(self.agent_path)
        prev0_did = prev0.get("agent_did") if isinstance(prev0, dict) else None
        if prev0_did and prev0_did != did_str and self.grant_status()[1].get("active"):
            return 409, {"error": "Stop your current agent first. Switching will not stop it - it keeps its "
                                  "permission until you sign a Stop.", "need": "stop"}
        nick = body.get("nick")
        nick = nick.strip()[:40] if isinstance(nick, str) else ""
        with self._grant_lock:
            prev = self._read_json(self.agent_path)
            prev_did = prev.get("agent_did") if isinstance(prev, dict) else None
            if prev_did and prev_did != did_str:
                self._revoke_and_clear_active()
            self._write_json(self.agent_path, {"agent_did": did_str, "nick": nick})
        return 200, {"ok": True, "agent_did": did_str, "nick": nick}

    def unlink_agent(self):
        if self.grant_status()[1].get("active"):
            return 409, {"error": "Stop your agent first. Unlinking will not stop it - it keeps its permission "
                                  "until you sign a Stop.", "need": "stop"}
        with self._grant_lock:
            self._revoke_and_clear_active()
            try:
                self.agent_path.unlink()
            except OSError:
                pass
        return 200, {"ok": True, "linked": False}

    def sign_grant(self, body):
        """body: {allow:{klass:ceiling}, duration_seconds, passphrase}. Signs the owner's grant
        (the signed allowlist) and stores it as the active grant. A ceiling of 0 means gated, so
        it is dropped (an empty allow is a valid grant that authorizes NOTHING on auto, the safe
        default). Signing ALWAYS demands the passphrase; the chat unlock never covers it."""
        agent = self._read_json(self.agent_path)
        agent_did = agent.get("agent_did") if isinstance(agent, dict) else None
        if not agent_did:
            return 400, {"error": "link your agent before signing a grant for it"}
        allow_in = body.get("allow")
        if not isinstance(allow_in, dict):
            return 400, {"error": "choose what your agent may do on its own"}
        known = {k["klass"] for k in GRANT_KNOBS}
        allow = {}
        for k, v in allow_in.items():
            if k not in known:
                return 400, {"error": "unknown permission: %s" % k}
            if isinstance(v, bool) or not isinstance(v, int):
                return 400, {"error": "each daily limit must be a whole number"}
            if v < 0:
                return 400, {"error": "a daily limit cannot be negative"}
            if v > 1_000_000:
                return 400, {"error": "a daily limit that high is effectively unlimited; keep it under 1,000,000"}
            if v > 0:
                allow[k] = v
        dur_raw = body.get("duration_seconds")
        if isinstance(dur_raw, bool) or not isinstance(dur_raw, int):
            return 400, {"error": "choose how long the grant lasts"}
        dur = dur_raw
        if dur < 3600 or dur > 7776000:
            return 400, {"error": "a grant lasts between 1 hour and 90 days"}
        return self._sign_store_publish(allow, dur, body.get("passphrase"), agent_did)

    def _sign_store_publish(self, allow, dur, passphrase, agent_did):
        """Build a grant for the linked agent, supersede the prior one, store it locally, and PUBLISH it
        to the owner slot so the agent's gateway reads it. Shared by sign_grant and the STOP (revoke = an
        empty-allow grant). DEMANDS the passphrase: in this trust model there is no keyless stop, a real
        network grant/stop must be signed by the owner key. The publish is INSIDE the grant lock so two
 concurrent signs cannot land in the slot out of order. The local store is the
        dashboard's source of truth; the publish is best-effort and its outcome is REPORTED, so the human
        is never told the agent received a grant/stop that did not actually reach it. Returns
        (status, response)."""
        priv = self.ks.load(passphrase or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        signed_allow = dict(allow)
        if signed_allow and "MODEL" not in signed_allow:
            signed_allow["MODEL"] = DEFAULT_MODEL_CEILING
        now = int(self.clock())
        grant_id = "g" + secrets.token_hex(5)
        try:
            grant = G.build_grant(priv, grant_id, agent_did, now, now + dur, signed_allow, window=G.DEFAULT_WINDOW_SECONDS)
        except Exception as e:
            return 400, {"error": "could not build the grant: %s" % e}
        finally:
            try:
                del priv
            except Exception:
                pass
        with self._grant_lock:
            self._revoke_and_clear_active()
            self._write_json(self.grant_path, grant)
            published, publish_detail = self._publish_grant(grant)
            self._record_grant_publish(grant_id, published)
        return 200, {"ok": True, "grant_id": grant_id, "expiry": now + dur, "allow": dict(allow),
                     "published": published, "publish_detail": publish_detail}

    def _record_grant_publish(self, grant_id, published):
        """Remember whether THIS grant reached the agent, so a failed publish can offer a persistent
        'Send again' across a reload. Best-effort; never fails the sign/resend it records."""
        try:
            self._write_json(self.grant_publish_path, {"grant_id": grant_id, "published": bool(published)})
        except Exception:
            pass

    def resend_grant(self):
        """Re-publish the ALREADY-SIGNED grant in grant.json to the owner slot. No re-sign, no passphrase:
        it only re-transports owner-signed bytes that were already authorized, so it creates no new
        authority, and never forces a full re-toggle + re-sign just to retry a transient publish.
        Reports `published` honestly. If there is no signed grant to resend, says so."""
        grant = self._read_json(self.grant_path)
        if not isinstance(grant, dict) or not grant.get("grant_id"):
            return 200, {"ok": False, "published": False,
                         "detail": "there is no signed grant to resend; sign one first"}
        with self._grant_lock:
            published, publish_detail = self._publish_grant(grant)
            self._record_grant_publish(grant.get("grant_id"), published)
        return 200, {"ok": True, "grant_id": grant.get("grant_id"),
                     "published": published, "publish_detail": publish_detail}

    def _publish_grant(self, grant):
        """Publish the owner-signed grant to the owner's SINGLE note slot: namespace did-<shard>, key
        <shardKey>-grant, both derived from the owner DID (a fixed owner-addressed slot, never a room
        scan). The note is transport only; the grant is self-authenticating and the agent's Governor
        gates on its configured owner key, so an unsigned note write is safe and a stranger can only
        overwrite the slot, never inject authority. Never raises: a publish failure must not undo the
        local sign. Returns (ok_bool, detail)."""
        try:
            owner_did = self.ks.public_did()
            if not owner_did:
                return False, "no owner identity to address the grant slot"
            ns = D.did_note_ns(owner_did)
            _, shard_key = D.note_shard_key(owner_did)
            value = json.dumps(grant, separators=(",", ":"))
            return self.pc.set_note(ns, shard_key + "-grant", value, confirm=True)
        except Exception as e:
            return False, "could not publish the grant to the protocol: %s" % e

    def grant_status(self):
        """The current grant, VERIFIED (a stored grant that does not verify against our own key,
        or is expired, or is revoked, is reported active:false, never trusted). Includes the knob
        catalog and, per active class, its ceiling and danger flag."""
        knobs = self.grant_catalog()
        agent = self.agent_status()[1]
        grant = self._read_json(self.grant_path)
        if not isinstance(grant, dict) or not grant.get("grant_id"):
            return 200, {"active": False, "knobs": knobs, "agent": agent, "allow": []}
        owner_did = self.ks.public_did()
        try:
            owner_pub = D.pub_raw_from_did(owner_did) if owner_did else None
        except Exception:
            owner_pub = None
        now = int(self.clock())
        try:
            revoked = self._read_revoked()
        except ValueError:
            revoked = None
        expected_agent = agent.get("agent_did")
        valid = (revoked is not None and expected_agent is not None
                 and G.verify_grant(owner_pub, grant, now=now, revoked_ids=revoked,
                                    expected_agent=expected_agent))
        allow = grant.get("allow") if isinstance(grant.get("allow"), dict) else {}
        allow_view = ([{"klass": k, "ceiling": allow[k], "dangerous": G.is_dangerous(k)}
                       for k in sorted(allow) if k != "MODEL"] if valid else [])
        try:
            expiry = int(grant.get("expiry"))
        except (TypeError, ValueError):
            expiry = now
        pub = self._read_json(self.grant_publish_path)
        unsent = bool(isinstance(pub, dict) and pub.get("grant_id") == grant.get("grant_id")
                      and pub.get("published") is False)
        return 200, {
            "active": bool(valid),
            "grant_id": grant.get("grant_id"),
            "issued": grant.get("issued"),
            "expiry": expiry,
            "window": grant.get("window"),
            "expires_in": max(0, expiry - now),
            "revoked": bool(revoked) and grant.get("grant_id") in revoked,
            "unsent": unsent,
            "agent_did": grant.get("agent_did"),
            "allow": allow_view,
            "knobs": knobs,
            "agent": agent,
        }

    def revoke_grant(self, body=None):
        """STOP the agent. A real stop is a re-signed EMPTY-allow grant published to the owner slot
        (Option A): the agent keeps existing but its auto-authority drops to zero, and the Governor's
        forward-only high-water makes the stop PERMANENT once a single ~1-min tick reads it. There is NO
        keyless stop in this trust model (a stop the agent will honour must be signed by the owner key),
        so this DEMANDS the passphrase exactly like signing, and it REPORTS whether the stop reached the
        agent (`published`) - it never tells the human the agent stopped when the write did not land.
        A passphraseless revoke that only cleared LOCAL state would leave the slot's last permissive
        grant in place, so the agent would run on until expiry while the UI claimed it had stopped."""
        body = body or {}
        agent = self._read_json(self.agent_path)
        agent_did = agent.get("agent_did") if isinstance(agent, dict) else None
        if not agent_did:
            with self._grant_lock:
                self._revoke_and_clear_active()
            return 200, {"ok": True, "active": False, "stopped": False, "published": False,
                         "detail": "no agent is linked, so there is nothing to stop on the network"}
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        now = int(self.clock())
        stop_id = "g" + secrets.token_hex(5)
        try:
            stop_grant = G.build_grant(priv, stop_id, agent_did, now, now + STOP_GRANT_SECONDS, {},
                                       window=G.DEFAULT_WINDOW_SECONDS)
        except Exception as e:
            return 400, {"error": "could not build the stop: %s" % e}
        finally:
            try:
                del priv
            except Exception:
                pass
        with self._grant_lock:
            self._revoke_and_clear_active()
            published, publish_detail = self._publish_grant(stop_grant)
        return 200, {"ok": True, "active": False, "stopped": bool(published),
                     "published": published, "publish_detail": publish_detail}

    def agent_feed(self):
        """What the public board shows of the linked agent RIGHT NOW: the jobs it posted or is
        working. Honest about its limit: the board is a fixed window and there is no per-DID feed,
        so this is what is observable, not a complete history. A fuller activity log is the agent's
        own to report in a later slice."""
        a = self._read_json(self.agent_path)
        if not isinstance(a, dict) or not a.get("agent_did"):
            return 200, {"linked": False, "items": []}
        agent_did = a["agent_did"]
        try:
            board = self.kc.read_board()
        except KC.KibbleError:
            return 200, {"linked": True, "agent_did": agent_did, "items": [],
                         "error": "could not reach the board"}
        items = []
        for j in board.get("jobs", []):
            if j.get("poster_did") == agent_did:
                role = "posted"
            elif j.get("worker_did") == agent_did:
                role = "working"
            else:
                continue
            items.append({"role": role, "category": j.get("category"), "title": j.get("title"),
                          "status": j.get("status"), "job_id": j.get("job_id"),
                          "useful_n": j.get("useful_n"), "not_n": j.get("not_n")})
        return 200, {"linked": True, "agent_did": agent_did, "items": items,
                     "note": "what the public board shows of your agent right now"}


    def _task_secret(self):
        """The slot secret shared owner<->gateway. Generated once on this machine and stored locally;
        the user sets the SAME value as the gateway's TASK_SECRET at deploy so both sides derive the
        same private slot key. It is NOT a key and NOT encryption (the honest ceiling: 'never posted
        publicly', not sealed mail); it only makes the slot unguessable. 48 hex chars, ample entropy.

 ABSENCE IS NOT INNOCENCE: a GENUINELY ABSENT file is a clean first run and we
        generate one; but a PRESENT-but-unreadable-or-empty file must RAISE, never be laundered into a
        NEW secret - because rotating it silently would publish every future playbook to a slot the
        already-deployed gateway (still holding the old TASK_SECRET) never reads, and we would report
        'sent' forever while the agent runs a stale list. Under a lock so a first-visit race cannot mint
        two different secrets."""
        with self._task_secret_lock:
            if self.task_secret_path.exists():
                s = self.task_secret_path.read_text("utf-8").strip()
                if not s:
                    raise ValueError("the task-secret file is present but empty/corrupt")
                return s
            s = secrets.token_hex(24)
            tmp = self.task_secret_path.with_suffix(".tmp")
            tmp.write_text(s, "utf-8")
            os.replace(tmp, self.task_secret_path)
            return s

    def _task_slot_key(self, secret):
        """The unguessable, valid-name slot key, derived IDENTICALLY to the gateway (agent/src/index.ts
        taskSlotKey): 't' + first 40 hex of sha256('flop-task-slot|' + secret). sha256 hex is lowercase
        [0-9a-f], so 't'+hex matches the note-name grammar."""
        h = hashlib.sha256(("flop-task-slot|" + secret).encode("utf-8")).hexdigest()
        return "t" + h[:40]

    def _next_task_nonce(self):
        """A strictly-increasing envelope nonce (ms clock, floored monotonic against a stored high-water),
        mirroring _next_say_nonce. v1 does not yet enforce it on the agent side, but signing a rising
        nonce now means the v2 replay guard (pin the highest seen task nonce) needs no envelope change."""
        with self._task_nonce_lock:
            try:
                prev = int(self.task_nonce_path.read_text("utf-8"))
            except Exception:
                prev = 0
            n = max(prev + 1, int(self.clock() * 1000))
            tmp = self.task_nonce_path.with_suffix(".tmp")
            tmp.write_text(str(n), "utf-8")
            os.replace(tmp, self.task_nonce_path)
            return n

    def _validate_tasks(self, raw):
        """Validate + normalise the incoming task list to EXACTLY what the gateway will accept, so what
        the user sees is what the agent gets (no silent post-signature truncation). Returns (tasks, err):
        a clean [{id,text,schedule}] list or (None, message). Bounds match agent/src/index.ts."""
        if not isinstance(raw, list):
            return None, "your tasks must be a list"
        if len(raw) > MAX_TASKS:
            return None, "keep it to a short playbook: at most %d tasks" % MAX_TASKS
        out, seen = [], set()
        for t in raw:
            if not isinstance(t, dict):
                return None, "each task must be an object"
            tid = t.get("id")
            if not (isinstance(tid, str) and _TASK_ID_RE.fullmatch(tid)):
                return None, "each task needs a short id (letters, digits, - or _)"
            if tid in seen:
                return None, "two tasks share the id %r; ids must be unique" % tid
            seen.add(tid)
            text = t.get("text")
            if not isinstance(text, str):
                return None, "the task %r has no text" % tid
            text = P.single_line(text)
            if not text:
                return None, "the task %r has no text" % tid
            if len(text) > MAX_TASK_LEN:
                return None, "the task %r is too long (max %d characters)" % (tid, MAX_TASK_LEN)
            sched = t.get("schedule")
            if sched not in TASK_SCHEDULES:
                return None, "the task %r needs a schedule (once / hourly / daily / weekly)" % tid
            out.append({"id": tid, "text": text, "schedule": sched})
        return out, None

    def tasks_status(self):
        """The Tasks tab state: the locally-saved current list, the seeded playbook to offer, the
        available schedules, whether an agent is linked (you cannot address a slot without an owner
        identity), and the deploy config (TASK_SECRET + chosen model) the user sets on the gateway."""
        saved = self._read_json(self.tasks_path)
        tasks = saved.get("tasks") if isinstance(saved, dict) else None
        cfg = self._read_json(self.config_path)
        model = cfg.get("model") if isinstance(cfg, dict) else None
        agent = self._read_json(self.agent_path)
        try:
            secret = self._task_secret()
            secret_error = None
        except Exception:
            secret, secret_error = None, "your task-secret file is unreadable; fix or remove it"
        return 200, {
            "tasks": tasks if isinstance(tasks, list) else [],
            "published": saved.get("published") if isinstance(saved, dict) else None,
            "updated": saved.get("updated") if isinstance(saved, dict) else None,
            "playbook": TASK_PLAYBOOK,
            "schedules": list(TASK_SCHEDULES),
            "max_tasks": MAX_TASKS,
            "max_task_len": MAX_TASK_LEN,
            "agent_linked": bool(isinstance(agent, dict) and agent.get("agent_did")),
            "has_key": self.ks.exists(),
            "deploy": {"task_secret": secret,
                       "secret_error": secret_error,
                       "model": model or DEFAULT_MODEL,
                       "model_choices": MODEL_CHOICES},
        }

    def save_tasks(self, body):
        """Sign the owner's task playbook into the private slot. body: {tasks:[{id,text,schedule}],
        passphrase}. Like the grant, this DEMANDS the passphrase: the envelope is owner-signed so a
        slot-finder cannot forge it. The whole signed envelope must fit ONE note, and the agent's read
        clamps that note in BYTES/UTF-16 units - so an over-size envelope would truncate on read, break
        the signature, and the agent would silently get NO tasks while we reported success. So we build
        the real envelope and REFUSE (writing + publishing nothing) if it exceeds MAX_ENVELOPE measured
        in UTF-8 BYTES (bytes >= UTF-16 units >= code points, so the byte ceiling dominates all three).
        A char-length check would let a multibyte playbook truncate, so the byte rule is enforced here
        too. The local tasks.json is our source of truth; the publish is best-effort and its outcome
        REPORTED, never assumed."""
        agent = self._read_json(self.agent_path)
        owner_did = self.ks.public_did()
        if not owner_did:
            return 400, {"error": "create your identity before sending tasks"}
        if not (isinstance(agent, dict) and agent.get("agent_did")):
            return 400, {"error": "link your agent before sending it tasks"}
        tasks, err = self._validate_tasks(body.get("tasks"))
        if err:
            return 400, {"error": err}
        try:
            secret = self._task_secret()
        except Exception:
            return 500, {"error": "your task-secret file is unreadable; fix or remove it and try again"}
        payload = json.dumps(tasks, separators=(",", ":"), ensure_ascii=False)
        key = self._task_slot_key(secret)
        ns = D.did_note_ns(owner_did)
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        now = int(self.clock())
        with self._task_lock:
            nonce = self._next_task_nonce()
            try:
                sig = D.sign_b64url(priv, P.note_sig_input(ns, key, canon_int(nonce, "nonce"), payload))
            except Exception as e:
                return 400, {"error": "could not sign the tasks: %s" % e}
            finally:
                try:
                    del priv
                except Exception:
                    pass
            envelope = json.dumps({"payload": payload, "nonce": nonce, "sig": sig},
                                  separators=(",", ":"), ensure_ascii=False)
            if len(envelope.encode("utf-8")) > MAX_ENVELOPE:
                return 400, {"error": "that playbook is too large to fit one note; use fewer or shorter tasks"}
            self._write_json(self.tasks_path, {"tasks": tasks, "updated": now, "published": None})
            try:
                published, detail = self.pc.set_note(ns, key, envelope, confirm=True)
            except Exception as e:
                published, detail = False, "could not reach the protocol: %s" % e
            self._write_json(self.tasks_path, {"tasks": tasks, "updated": now, "published": published})
        return 200, {"ok": True, "count": len(tasks), "published": published, "publish_detail": detail}

    def save_config(self, body):
        """Store the deploy-time config the user chose (currently the model). Local only; it is applied
        by setting it on the gateway at deploy. No passphrase: this signs nothing and touches no key."""
        model = body.get("model")
        if not (isinstance(model, str) and model.strip()):
            return 400, {"error": "choose a model"}
        if len(model) > 128 or not re.fullmatch(r"[A-Za-z0-9@/._:-]+", model):
            return 400, {"error": "that does not look like a model id"}
        with self._config_lock:
            cfg = self._read_json(self.config_path)
            if not isinstance(cfg, dict):
                cfg = {}
            cfg["model"] = model
            self._write_json(self.config_path, cfg)
        return 200, {"ok": True, "model": model}


    WAKE_CHOICES = (1, 5, 10, 15, 30, 60)

    def _next_config_nonce(self):
        """Strictly-increasing nonce for the config slot (ms clock floored monotonic), so a stranger
        cannot roll the setting back to an older signed value. Mirrors _next_task_nonce exactly."""
        with self._config_nonce_lock:
            try:
                prev = int(self.config_nonce_path.read_text("utf-8"))
            except Exception:
                prev = 0
            n = max(prev + 1, int(self.clock() * 1000))
            tmp = self.config_nonce_path.with_suffix(".tmp")
            tmp.write_text(str(n), "utf-8")
            os.replace(tmp, self.config_nonce_path)
            return n

    def _config_slot(self, owner_did):
        """The owner-addressed config slot, derived like the grant slot: a fixed owner-owned note key,
        never a room scan. Owner-signed, so an unsigned overwrite by a stranger cannot inject a setting
        (the reader verifies the signature against the configured owner key)."""
        ns = D.did_note_ns(owner_did)
        _, shard_key = D.note_shard_key(owner_did)
        return ns, shard_key + "-config"

    def save_cost_config(self, body):
        """Sign {model, wake} into the owner config slot so the gateway/agent apply it LIVE, no redeploy
        (Francisco's locked cost-UX decision). DEMANDS the passphrase like the grant: a setting the agent
        obeys must be owner-authenticated. Model is NOT allowlisted (all Cloudflare text models + free
        entry): a bad id fails CLOSED at the gateway (MODEL_ERROR) and the health light shows it, never a
        silent wrong-model. The nonce rises so an older setting cannot be replayed over a newer one."""
        model = body.get("model")
        wake = body.get("wake")
        if not (isinstance(model, str) and model.strip()):
            return 400, {"error": "choose a model"}
        model = model.strip()
        if len(model) > 128 or not re.fullmatch(r"[A-Za-z0-9@/._:-]+", model):
            return 400, {"error": "that does not look like a model id"}
        if isinstance(wake, bool) or wake not in self.WAKE_CHOICES:
            return 400, {"error": "wake interval must be one of %s minutes" % (self.WAKE_CHOICES,)}
        owner_did = self.ks.public_did()
        if not owner_did:
            return 400, {"error": "create your identity first"}
        payload = json.dumps({"model": model, "wake": wake}, separators=(",", ":"))
        ns, key = self._config_slot(owner_did)
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        now = int(self.clock())
        with self._cost_lock:
            nonce = self._next_config_nonce()
            try:
                sig = D.sign_b64url(priv, P.note_sig_input(ns, key, canon_int(nonce, "nonce"), payload))
            except Exception as e:
                return 400, {"error": "could not sign the settings: %s" % e}
            finally:
                try:
                    del priv
                except Exception:
                    pass
            envelope = json.dumps({"payload": payload, "nonce": nonce, "sig": sig},
                                  separators=(",", ":"), ensure_ascii=False)
            self._write_json(self.cost_config_path,
                             {"model": model, "wake": wake, "updated": now, "published": None})
            try:
                published, detail = self.pc.set_note(ns, key, envelope, confirm=True)
            except Exception as e:
                published, detail = False, "could not reach the protocol: %s" % e
            self._write_json(self.cost_config_path,
                             {"model": model, "wake": wake, "updated": now, "published": published})
        return 200, {"ok": True, "model": model, "wake": wake,
                     "published": published, "publish_detail": detail}

    def _current_wake(self):
        """The wake interval we expect the agent to report on, for the health freshness window. The last
        SIGNED cost config if any, else the DEPLOYED wake, else 15. Never raises."""
        cur = self._read_json(self.cost_config_path)
        w = cur.get("wake") if isinstance(cur, dict) else None
        if w in self.WAKE_CHOICES:
            return w
        _, dep_wake = self._deployed_config()
        return dep_wake or 15

    def _model_health(self):
        """The model-health light. The GATEWAY writes a SIGNED health note ({payload:{status,model,ts},
        nonce, sig}) to the agent's own <shardKey>-health slot after each model call; we read it and
        RE-VERIFY under the agent did, so a stranger's overwrite of the world-writable slot cannot fake
        an 'ok' (a bad signature reads as 'no valid report'). We also flag a STALE report (older than a
        few wake intervals) rather than trusting a possibly-replayed old 'ok'. Display only (M4): a
        health note authorizes nothing; the worst a poisoned one does is mislead this light."""
        agent = self._read_json(self.agent_path)
        agent_did = agent.get("agent_did") if isinstance(agent, dict) else None
        if not agent_did:
            return {"status": "unknown", "detail": "link your agent to see its model health"}
        try:
            ns = D.did_note_ns(agent_did)
            _, shard = D.note_shard_key(agent_did)
            raw = self.pc.get_note(ns, shard + "-health")
        except Exception:
            return {"status": "unknown", "detail": "could not read the health report"}
        if not raw:
            return {"status": "unknown", "detail": "no report yet"}
        try:
            env = json.loads(raw)
            payload = env.get("payload")
            sig = env.get("sig")
            if not isinstance(payload, str) or not isinstance(sig, str):
                return {"status": "unknown", "detail": "no valid report"}
            nonce_canon = canon_int(env.get("nonce"), "nonce")
            if not D.verify_by_did(agent_did, sig, P.note_sig_input(ns, shard + "-health", nonce_canon, payload)):
                return {"status": "unknown", "detail": "the health report did not verify (ignored)"}
            rec = json.loads(payload)
        except Exception:
            return {"status": "unknown", "detail": "no valid report"}
        if not isinstance(rec, dict):
            return {"status": "unknown", "detail": "no valid report"}
        ts = rec.get("ts")
        model = rec.get("model") if isinstance(rec.get("model"), str) else ""
        status_raw = rec.get("status")
        stale_after = max(self._current_wake() * 3 * 60, 20 * 60)
        SKEW = 300
        ok_ts = isinstance(ts, (int, float)) and not isinstance(ts, bool) and math.isfinite(ts)
        age = (self.clock() - ts) if ok_ts else None
        if age is None or age < -SKEW or age > stale_after:
            return {"status": "stale", "model": model,
                    "detail": "no recent report; the agent may be paused, stopped, or unreachable"}
        disp = max(0, int(age))
        if status_raw == "OK":
            return {"status": "ok", "model": model, "detail": "answered %ds ago" % disp}
        if status_raw == "MODEL_GATED":
            return {"status": "paused", "model": model, "detail": "the agent is stopped or out of budget"}
        return {"status": "error", "model": model, "detail": "the model did not answer; try another model"}

    def _deployed_config(self):
        """The model + wake the DEPLOY set on the agent (recorded into agent_config.json by the deploy
        engine and the model picker). This is what the agent actually runs until the owner signs a
        post-deploy cost config, so the cost panel must seed from it, not a hardcoded default. Never raises."""
        cfg = self._read_json(self.config_path)
        cfg = cfg if isinstance(cfg, dict) else {}
        model = cfg.get("model") if isinstance(cfg.get("model"), str) else None
        wake = cfg.get("wake") if cfg.get("wake") in self.WAKE_CHOICES else None
        return model, wake

    def cost_config_status(self):
        """The dashboard cost panel: what the agent is ACTUALLY running now, the choices to offer, and
        the model-health light. Truth ordering, so the panel never shows a hardcoded default as if it
        were live while the agent runs the deployed model: a SIGNED owner config
        wins; otherwise the DEPLOYED values from agent_config.json; the health note's model is the
        ground truth of what the gateway last actually called, so it labels the running line."""
        cur = self._read_json(self.cost_config_path)
        cur = cur if isinstance(cur, dict) else {}
        dep_model, dep_wake = self._deployed_config()
        health = self._model_health()
        signed = bool(cur.get("model"))
        if signed:
            model = cur.get("model")
            wake = cur.get("wake") if cur.get("wake") in self.WAKE_CHOICES else (dep_wake or 15)
            source = "signed"
        else:
            model = dep_model or DEFAULT_MODEL
            wake = dep_wake or 15
            source = "deployed" if (dep_model or dep_wake) else "default"
        running_model = health.get("model") if isinstance(health, dict) and health.get("model") else model
        return 200, {
            "model": model,
            "wake": wake,
            "source": source,
            "running_model": running_model,
            "published": cur.get("published"),
            "updated": cur.get("updated"),
            "wake_choices": list(self.WAKE_CHOICES),
            "model_choices": MODEL_CHOICES,
            "health": health,
        }

    def reject(self, body):
        """Reject a pending gated action: move it to decided as rejected, so it never signs and
        never shows again. Recoverable-check first (a bad id is a 404), then the atomic claim."""
        rid = body.get("request_id")
        item = self._load_item(rid) if rid else None
        if item is None:
            return 404, {"error": "no such pending request"}
        src = self.pending / (rid + ".json")
        dst = self.decided / (rid + ".json")
        try:
            os.replace(src, dst)
        except OSError:
            return 409, {"error": "this request is already being handled"}
        dst.write_text(json.dumps({"item": item, "rejected": True}, indent=2), "utf-8")
        return 200, {"ok": True, "rejected": rid}

    def approve(self, body):
        """body: {request_id, commit, passphrase}. Returns (status_code, dict)."""
        rid = body.get("request_id")
        item = self._load_item(rid) if rid else None
        if item is None:
            return 404, {"error": "no such pending request"}
        try:
            self._check_destination(item)
            view = A.approval_view(item["verb"], item.get("target"), item.get("verdict"))
        except Exception as e:
            return 409, {"error": "this proposal cannot be bound: %s" % e}
        if body.get("commit") != view["action_commit"]:
            return 409, {"need": "reread", "error": "what you saw no longer matches the "
                         "request; re-read it before approving"}
        priv = self.ks.load(body.get("passphrase") or "")
        if priv is None:
            return 403, {"need": "passphrase", "error": "the passphrase did not unlock the key"}
        src = self.pending / (rid + ".json")
        claim = self.decided / (rid + ".json")
        try:
            os.replace(src, claim)
        except OSError:
            del priv
            return 409, {"error": "this request is already being handled"}
        try:
            nonce = self._next_nonce()
            expiry = int(self.clock()) + EXPIRY_SECONDS
            steer = S.build_steer(priv, item["destination"], view["action_string"], nonce, expiry)
        finally:
            del priv
        delivered = self.writer(item["destination"], steer, item) if self.writer is not None else None
        claim.write_text(json.dumps({"item": item, "steer": steer}, indent=2), "utf-8")
        return 200, {"ok": True, "steer": steer, "delivered": delivered}


    def create_key(self, body):
        try:
            did_str, generated = self.ks.generate(None if body.get("generate") else body.get("passphrase"))
        except keystore.KeyError_ as e:
            return 400, {"error": str(e)}
        self._forget_path()
        out = {"ok": True, "did": did_str}
        if generated:
            out["passphrase"] = generated
        return 200, out

    def import_key(self, body):
        try:
            did_str = self.ks.import_pem((body.get("pem") or "").encode("utf-8"), body.get("passphrase") or "")
        except keystore.KeyError_ as e:
            return 400, {"error": str(e)}
        self._forget_path()
        return 200, {"ok": True, "did": did_str}

    def export_key(self):
        try:
            return 200, self.ks.export_pem()
        except keystore.KeyError_ as e:
            return 400, json.dumps({"error": str(e)}).encode("utf-8")


def make_handler(dash):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _host_ok(self):
            return self.headers.get("Host") == "%s:%d" % (dash.host, dash.port)

        def _origin_ok(self):
            return self.headers.get("Origin") == dash.origin

        def _send(self, code, obj, raw=False):
            data = obj if raw else json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream" if raw else "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return {}
            try:
                obj = json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                return {}
            return obj if isinstance(obj, dict) else {}

        def _serve_static(self, entry):
            fname, ctype = entry
            p = WEB_DIR / fname
            try:
                data = p.read_bytes()
            except OSError:
                return self._send(404, {"error": "not built"})
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            parsed = urlparse(self.path)
            path, q = parsed.path, parse_qs(parsed.query)
            if path in _STATIC:
                return self._serve_static(_STATIC[path])
            if path == "/api/status":
                return self._send(200, dash.status())
            if path == "/api/pending":
                return self._send(200, dash.pending_cards())
            if path == "/api/rooms":
                return self._send(*dash.list_rooms())
            if path == "/api/room":
                room = (q.get("room") or [None])[0]
                since = (q.get("since") or [None])[0]
                return self._send(*dash.read_room(room, since=since))
            if path == "/api/chat/status":
                return self._send(*dash.chat_status())
            if path == "/api/board":
                return self._send(*dash.list_board())
            if path == "/api/board/mine":
                return self._send(*dash.my_jobs())
            if path == "/api/agent":
                return self._send(*dash.agent_status())
            if path == "/api/agent/feed":
                return self._send(*dash.agent_feed())
            if path == "/api/grant":
                return self._send(*dash.grant_status())
            if path == "/api/tasks":
                return self._send(*dash.tasks_status())
            if path == "/api/key/export":
                code, data = dash.export_key()
                return self._send(code, data, raw=True)
            if path == "/api/deploy/status":
                return self._send(*dash.deploy.deploy_status())
            if path == "/api/deploy/connection":
                return self._send(*dash.deploy.connection_status())
            if path == "/api/cost":
                return self._send(*dash.cost_config_status())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            if not self._origin_ok():
                return self._send(403, {"error": "bad origin"})
            body = self._body()
            path = urlparse(self.path).path
            if path == "/api/approve":
                return self._send(*dash.approve(body))
            if path == "/api/room/say":
                return self._send(*dash.say(body))
            if path == "/api/chat/unlock":
                return self._send(*dash.unlock_chat(body))
            if path == "/api/chat/lock":
                return self._send(*dash.lock_chat())
            if path == "/api/board/post":
                return self._send(*dash.post_job(body))
            if path == "/api/agent/link":
                return self._send(*dash.link_agent(body))
            if path == "/api/agent/unlink":
                return self._send(*dash.unlink_agent())
            if path == "/api/grant/sign":
                return self._send(*dash.sign_grant(body))
            if path == "/api/grant/revoke":
                return self._send(*dash.revoke_grant(body))
            if path == "/api/grant/resend":
                return self._send(*dash.resend_grant())
            if path == "/api/tasks/save":
                return self._send(*dash.save_tasks(body))
            if path == "/api/config/save":
                return self._send(*dash.save_config(body))
            if path == "/api/cost/save":
                return self._send(*dash.save_cost_config(body))
            if path == "/api/onboarding/choose":
                return self._send(*dash.choose_path(body))
            if path == "/api/onboarding/reset":
                return self._send(*dash.reset_path())
            if path == "/api/deploy/login":
                return self._send(*dash.deploy.connect())
            if path == "/api/deploy/start":
                return self._send(*dash.deploy.start(body))
            if path == "/api/pending/reject":
                return self._send(*dash.reject(body))
            if path == "/api/key/create":
                return self._send(*dash.create_key(body))
            if path == "/api/key/import":
                return self._send(*dash.import_key(body))
            return self._send(404, {"error": "not found"})

    return Handler


def serve(state_dir, host=HOST, port=PORT, writer=None):
    dash = Dashboard(state_dir, host, port, writer=writer)
    httpd = ThreadingHTTPServer((host, port), make_handler(dash))
    return httpd, dash


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Flop Social dashboard - runs on your own machine, holds your key.")
    ap.add_argument("--state-dir", default=str(Path(__file__).resolve().parent / "state"),
                    help="where your identity, grant and tasks are stored (default: dashboard/state)")
    ap.add_argument("--host", default=HOST, help="bind address (default 127.0.0.1; keep it local)")
    ap.add_argument("--port", type=int, default=PORT, help="port (default %d)" % PORT)
    args = ap.parse_args()

    httpd, _dash = serve(args.state_dir, host=args.host, port=args.port)
    url = "http://%s:%d" % (args.host, args.port)
    print("Flop dashboard is running.")
    print("  Open this EXACT address in your browser:  " + url)
    print("  (use this address, not 'localhost' - the local guard checks it)")
    print("  Your data is stored in: " + args.state_dir)
    print("  Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
