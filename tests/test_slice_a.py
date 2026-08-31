"""Oracle for the Slice A frontend (dashboard/web/) wired to the real local server, driven
over a real socket. Proves the static app is served whole, the setup APIs create/report/
export a real owner key, overwrite is refused, and the POST guard and path whitelist hold
behind the app. Temp state dir only (mkdtemp); never touches a real key. ASCII only.
"""
import http.client
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dashboard"))
import server as srv  # noqa: E402

HOST, PORT = "127.0.0.1", 8799
state = Path(tempfile.mkdtemp(prefix="slicea_"))
httpd, dash = srv.serve(str(state), host=HOST, port=PORT)
threading.Thread(target=httpd.serve_forever, daemon=True).start()

FAILS = []


def check(name, cond):
    sys.stdout.write(("PASS " if cond else "FAIL ") + name + "\n")
    if not cond:
        FAILS.append(name)


def req(method, path, body=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=5)
    headers = {"Host": "%s:%d" % (HOST, PORT)}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Origin"] = "http://%s:%d" % (HOST, PORT)
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    raw = r.read()
    c.close()
    return r.status, r.getheader("Content-Type"), raw


st, ct, raw = req("GET", "/")
check("GET / returns 200 html", st == 200 and ct.startswith("text/html"))
check("index.html carries the FLOP shell", b"<title>FLOP Dashboard</title>" in raw and b'id="app"' in raw)
check("index.html links style.css and app.js", b'href="/style.css"' in raw and b'src="/app.js"' in raw)
st, ct, raw = req("GET", "/style.css")
check("GET /style.css is css with the design tokens", st == 200 and ct.startswith("text/css") and b"--human" in raw)
st, ct, raw = req("GET", "/app.js")
check("GET /app.js is javascript with the setup wiring", st == 200 and ct.startswith("application/javascript") and b"createKey" in raw)

st, ct, raw = req("GET", "/api/status")
d = json.loads(raw)
check("status before setup reports has_key false", st == 200 and d.get("has_key") is False)

st, ct, raw = req("POST", "/api/key/create", {"generate": True})
d = json.loads(raw)
check("create(generate) returns ok + a did:key", st == 200 and d.get("ok") and str(d.get("did", "")).startswith("did:key:z6Mk"))
check("create(generate) echoes a strong passphrase once", isinstance(d.get("passphrase"), str) and len(d["passphrase"]) >= 20)
gen_did = d["did"]

st, ct, raw = req("GET", "/api/status")
d = json.loads(raw)
check("status after setup reports the same did", d.get("has_key") and d.get("did") == gen_did)
check("status exposes a fingerprint", bool(d.get("fingerprint")))

st, ct, raw = req("GET", "/api/key/export")
check("export returns the encrypted PEM", st == 200 and raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

st, ct, raw = req("POST", "/api/key/create", {"generate": True})
d = json.loads(raw)
check("a second create is refused (no overwrite)", st == 400 and "error" in d)

c = http.client.HTTPConnection(HOST, PORT, timeout=5)
c.request("POST", "/api/key/create",
          body=json.dumps({"generate": True}).encode("utf-8"),
          headers={"Host": "%s:%d" % (HOST, PORT), "Content-Type": "application/json"})
r = c.getresponse()
r.read()
c.close()
check("POST with no Origin is 403", r.status == 403)

st, ct, raw = req("GET", "/../server.py")
check("a traversal attempt is not served", st in (400, 404))

httpd.shutdown()
sys.stdout.write("----\n")
sys.stdout.write("ALL PASS\n" if not FAILS else ("FAILURES: " + ", ".join(FAILS) + "\n"))
sys.exit(1 if FAILS else 0)
