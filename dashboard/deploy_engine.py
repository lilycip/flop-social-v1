"""Path A deploy engine: the dashboard drives the Cloudflare deploy of the two Workers so a
non-technical user never opens a terminal. It wraps the PROVEN manual runbook (docs/DEPLOY.md,
steps 0-4) as a sequenced, progress-reporting job.

SECURITY INVARIANTS enforced here and asserted by tests (test_deploy.py):
  1. The agent SEED never appears in a log line, a progress `detail`, or any API response. It
     flows only from the minted key into the STDIN of `wrangler secret put`, held in one local
     that is dropped straight after. Progress details are FIXED strings we write, never wrangler
     output; wrangler stderr kept on failure is secret-scrubbed and truncated.
  2. Every wrangler call is an argv LIST run with shell=False (via `node .../wrangler.js`, which
     also dodges the Windows .cmd shim). User-supplied name/model are validated against a strict
     grammar before they can reach an argument, so nothing shell-special is constructible.
  3. OWNER_DID is the dashboard's OWN did (keystore), never user free text. There is no Cloudflare
     token here at all: `wrangler login` authenticates in the browser and wrangler holds it; the
     engine never sees, stores, or sets a token, and never makes it a Worker secret.
  4. Fail-safe: any failed step halts the sequence and the engine never advances to a half-open
     state. A missing secret leaves the gateway doing nothing (it never opens anything). A
     re-deploy NEVER re-mints over an existing agent identity; it reopens it.
"""
import json
import re
import subprocess
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import keystore


NICK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$")
MODEL_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._/\-]{2,79}$")
WAKE_CHOICES = (1, 5, 10, 15, 30, 60)

_SECRETISH = re.compile(r"[A-Fa-f0-9]{40,}|[A-Za-z0-9_\-]{60,}")


def _scrub(s):
    """Redact secret-shaped runs and truncate. Used ONLY on wrangler stderr kept for a failed
    step, so a value that should never have been printed cannot leak through an error detail."""
    if not s:
        return ""
    return _SECRETISH.sub("[redacted]", s)[:300]


AGENT_HEARTBEAT_CRON = "* * * * *"


def _real_runner(argv, cwd=None, stdin=None, timeout=None):
    """Run one argv list with shell=False. Returns (returncode, stdout, stderr) as text. stdin,
    if given, is bytes piped to the child (the seed / task secret path). Never raises on a
    non-zero exit; a timeout or spawn failure is reported as a non-zero code with the reason."""
    try:
        p = subprocess.run(argv, cwd=cwd, input=stdin, capture_output=True,
                           shell=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except OSError as e:
        return 127, "", str(e)
    out = (p.stdout or b"").decode("utf-8", "replace")
    err = (p.stderr or b"").decode("utf-8", "replace")
    return p.returncode, out, err


_STEPS = [
    ("account", "Connect Cloudflare"),
    ("preflight", "Check the configuration"),
    ("identity", "Create your agent's identity"),
    ("gateway", "Deploy the secure gateway"),
    ("secrets", "Seal your agent's key"),
    ("agent", "Deploy your agent"),
    ("finalize", "Finish and link it"),
]


class DeployEngine:
    def __init__(self, dash, runner=None, node_bin="node", wrangler_js=None, agent_dir=None):
        self.dash = dash
        self.run = runner or _real_runner
        self.node = node_bin
        self.agent_dir = Path(agent_dir) if agent_dir else (
            Path(__file__).resolve().parent.parent / "agent")
        self.wrangler_js = str(wrangler_js) if wrangler_js else str(
            self.agent_dir / "node_modules" / "wrangler" / "bin" / "wrangler.js")
        self.gw_cfg = str(self.agent_dir / "wrangler.jsonc")
        self.agent_cfg = str(self.agent_dir / "wrangler.agent.jsonc")
        self.id_dir = self.dash.dir / "agent-id"
        self.deploy_state_path = self.dash.dir / "deploy.json"
        self._lock = threading.Lock()
        self._thread = None
        self._login_thread = None
        self._steps = [{"key": k, "title": t, "status": "pending", "detail": ""} for k, t in _STEPS]
        self._overall = self._read_overall()


    def _read_overall(self):
        try:
            rec = json.loads(self.deploy_state_path.read_text("utf-8"))
            return "live" if rec.get("status") == "live" else "idle"
        except Exception:
            return "idle"

    def deploy_status(self):
        rec = None
        try:
            rec = json.loads(self.deploy_state_path.read_text("utf-8"))
        except Exception:
            rec = None
        with self._lock:
            overall = self._overall
            snap = {"overall": overall, "steps": [dict(s) for s in self._steps]}
        if isinstance(rec, dict) and rec.get("status") == "live":
            snap["our_did"] = rec.get("our_did")
            if overall == "idle":
                snap["overall"] = "live"
        return 200, snap


    def connect(self):
        """Start `wrangler login` in the background (it opens the browser and blocks until the
        user signs in). Non-blocking: the frontend polls connection_status until it flips to
        connected. We never see a token; wrangler stores it in its own config dir, never here."""
        with self._lock:
            if self._login_thread and self._login_thread.is_alive():
                return 200, {"started": True}
            self._login_thread = threading.Thread(target=self._do_login, daemon=True)
            self._login_thread.start()
        return 200, {"started": True}

    def _do_login(self):
        self.run([self.node, self.wrangler_js, "login"], cwd=str(self.agent_dir), timeout=300)

    def _logged_in(self):
        rc, out, _ = self.run([self.node, self.wrangler_js, "whoami"],
                              cwd=str(self.agent_dir), timeout=30)
        return rc == 0 and "not authenticated" not in (out or "").lower()

    def connection_status(self):
        return 200, {"connected": bool(self._logged_in())}


    def start(self, body):
        name = (body or {}).get("agent_name")
        model = (body or {}).get("model")
        wake = (body or {}).get("wake")
        if not isinstance(name, str) or not NICK_RE.match(name):
            return 400, {"error": "agent name must be 1-32 letters, digits, spaces, - or _"}
        if not isinstance(model, str) or not MODEL_RE.match(model):
            return 400, {"error": "that model id is not a valid Cloudflare model name"}
        if isinstance(wake, bool) or wake not in WAKE_CHOICES:
            return 400, {"error": "wake interval must be one of %s minutes" % (WAKE_CHOICES,)}
        with self._lock:
            if self._thread and self._thread.is_alive():
                return 409, {"error": "a deploy is already running"}
            for s in self._steps:
                s["status"], s["detail"] = "pending", ""
            self._overall = "running"
            self._thread = threading.Thread(
                target=self._run, args=(name, model, wake), daemon=True)
            self._thread.start()
        return 200, self.deploy_status()[1]

    def _set(self, key, status, detail=""):
        with self._lock:
            for s in self._steps:
                if s["key"] == key:
                    s["status"], s["detail"] = status, detail
                    break

    def _fail(self, key, detail):
        self._set(key, "failed", detail)
        with self._lock:
            self._overall = "failed"

    def _run(self, name, model, wake):
        try:
            self._run_steps(name, model, wake)
        except Exception as e:
            with self._lock:
                cur = next((s for s in self._steps if s["status"] == "running"), None)
                if cur:
                    cur["status"], cur["detail"] = "failed", _scrub(str(e)) or "unexpected error"
                self._overall = "failed"

    def _run_steps(self, name, model, wake):
        self._set("account", "running")
        if not self._logged_in():
            return self._fail("account", "Connect your Cloudflare account first.")
        self._set("account", "ok", "Signed in to Cloudflare.")

        self._set("preflight", "running")
        rc, out, err = self.run([self.node, "tools/check_deploy.mjs"],
                                cwd=str(self.agent_dir), timeout=60)
        if rc != 0:
            miss = "\n".join(l for l in (out or "").splitlines() if "[MISS]" in l)
            return self._fail("preflight",
                              _scrub(miss) or _scrub(out or err) or "the configuration check failed")
        self._set("preflight", "ok", "Configuration looks good.")

        self._set("identity", "running")
        owner_did = self.dash.ks.public_did()
        if not owner_did:
            return self._fail("identity", "Create your own identity first.")
        try:
            our_did, seed = self._agent_identity()
        except Exception as e:
            return self._fail("identity", _scrub(str(e)) or "could not create the agent identity")
        self._set("identity", "ok", "Your agent's identity is ready.")

        # Invalidate any prior deploy record NOW - the gateway deploy below is the first thing that
        # changes the gateway's MODEL_NAME, so a failure from here on must not leave a stale 'live'
        # record naming the OLD model. The pure checks above (account/preflight/identity) change nothing
        # on Cloudflare, so invalidating before them would wrongly wipe a good record.
        self.dash._write_json(self.dash.deploy_state_path, {"status": "deploying"})
        self._set("gateway", "running")
        rc, _, err = self.run(
            [self.node, self.wrangler_js, "deploy", "-c", self.gw_cfg,
             "--var", "OUR_DID:" + our_did,
             "--var", "OWNER_DID:" + owner_did,
             "--var", "MODEL_NAME:" + model],
            cwd=str(self.agent_dir), timeout=300)
        if rc != 0:
            seed = None
            return self._fail("gateway", _scrub(err) or "the gateway did not deploy")
        self._set("gateway", "ok", "The secure gateway is live.")

        self._set("secrets", "running")
        rc, _, err = self.run(
            [self.node, self.wrangler_js, "secret", "put", "KEY_SEED", "-c", self.gw_cfg],
            cwd=str(self.agent_dir), stdin=(seed + "\n").encode("utf-8"), timeout=60)
        seed = None
        if rc != 0:
            return self._fail("secrets", _scrub(err) or "sealing the key failed")
        task_secret = self.dash._task_secret()
        rc, _, err = self.run(
            [self.node, self.wrangler_js, "secret", "put", "TASK_SECRET", "-c", self.gw_cfg],
            cwd=str(self.agent_dir), stdin=(task_secret + "\n").encode("utf-8"), timeout=60)
        task_secret = None
        if rc != 0:
            return self._fail("secrets", _scrub(err) or "sealing the task secret failed")
        self._set("secrets", "ok", "Your agent's key is sealed into Cloudflare.")

        self._set("agent", "running")
        rc, _, err = self.run(
            [self.node, self.wrangler_js, "deploy", "-c", self.agent_cfg,
             "--var", "NICK:" + name, "--var", "WAKE_MINUTES:" + str(wake),
             "--triggers", AGENT_HEARTBEAT_CRON],
            cwd=str(self.agent_dir), timeout=300)
        if rc != 0:
            return self._fail("agent", _scrub(err) or "the agent did not deploy")
        self._set("agent", "ok", "Your agent is deployed.")

        self._set("finalize", "running")
        code, _ = self.dash.link_agent({"agent_did": our_did, "nick": name})
        self._record_config(model, wake, our_did)
        if code == 200:
            self._set("finalize", "ok", "Linked. Your dashboard is ready.")
        else:
            self._set("finalize", "ok",
                      "Deployed. Stop your current agent, then link this one on the My Agent tab.")
        with self._lock:
            self._overall = "live"


    def _agent_identity(self):
        """Return (our_did, seed_hex). Mint a fresh sealed identity on first deploy; on a
        re-deploy reopen the existing one (NEVER re-mint over it). The 'fully automatic' path:
        the generated passphrase is kept in a 0600 sidecar so re-deploys
        are one-click; the encrypted PEM + sidecar are the local backup, the seed's real home is
        the sealed Cloudflare secret."""
        import os
        import secrets as _secrets
        ks = keystore.Keystore(self.id_dir)
        side = self.id_dir / "owner.passphrase"
        if ks.exists():
            pw = side.read_text("utf-8").strip() if side.exists() else ""
            priv = ks.load(pw)
            if priv is None:
                raise RuntimeError("the agent identity exists but its saved passphrase did not open it")
        elif ks.stranded():
            raise RuntimeError("the agent identity files are damaged (one is present, one is missing). "
                               "Move the 'agent-id' folder aside to deploy a fresh agent.")
        else:
            passphrase = _secrets.token_urlsafe(18)
            self.id_dir.mkdir(parents=True, exist_ok=True)
            side.write_text(passphrase, "utf-8")
            try:
                os.chmod(side, 0o600)
            except OSError:
                pass
            ks.generate(passphrase)
            priv = ks.load(passphrase)
            if priv is None:
                raise RuntimeError("the agent identity was created but could not be reopened")
        seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()).hex()
        return ks.public_did(), seed

    def _record_config(self, model, wake, our_did):
        # The AUTHORITATIVE deploy record: what a real deploy set, bound to the agent DID it deployed.
        # The cost panel reads THIS (not the Tasks-tab picker's pre-deploy choice) and only trusts it
        # when our_did matches the linked agent, so a picker click or a stale record can never
        # masquerade as what is actually running.
        self.dash._write_json(self.dash.deploy_state_path,
                              {"status": "live", "our_did": our_did, "model": model, "wake": wake})
