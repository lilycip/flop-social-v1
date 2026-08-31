"""Run every Flop Social v1 test suite and report one total. Each suite exits non-zero on
any failure; this runner surfaces which suite failed. python tests/run_all.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITES = ["test_shared.py", "test_grant.py", "test_keystore.py", "test_server.py", "test_slice_a.py", "test_slice_b.py", "test_slice_c.py", "test_slice_d.py"]

failed = []
for s in SUITES:
    r = subprocess.run([sys.executable, str(HERE / s)], capture_output=True, text=True)
    passes = r.stdout.count("PASS ")
    ok = r.returncode == 0
    sys.stdout.write("%-22s %3d checks  %s\n" % (s, passes, "OK" if ok else "FAILED"))
    if not ok:
        failed.append(s)
        sys.stdout.write(r.stdout[-2000:])
        sys.stdout.write(r.stderr[-2000:])

sys.stdout.write("----\n")
sys.stdout.write("ALL SUITES PASS\n" if not failed else ("FAILED: " + ", ".join(failed) + "\n"))
sys.exit(1 if failed else 0)
