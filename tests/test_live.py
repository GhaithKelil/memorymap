"""Live tests against real processes (Windows only)."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="needs the Win32 memory APIs")

from memorymap.diff import RESIDUE, diff_snapshots  # noqa: E402
from memorymap.scan import run_scan  # noqa: E402

DEMO = Path(__file__).resolve().parent.parent / "examples" / "demo_target.py"


def readline(proc, timeout=30):
    """readline() that cannot hang the suite: a watchdog kills the child if it goes quiet."""
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        return proc.stdout.readline()
    finally:
        timer.cancel()


@pytest.fixture
def demo(tmp_path):
    flag = tmp_path / "logout.flag"
    env = {**os.environ, "MEMORYMAP_DEMO_FLAG": str(flag)}
    proc = subprocess.Popen([sys.executable, "-u", str(DEMO)], stdout=subprocess.PIPE, text=True, env=env)
    try:
        pid = int(readline(proc).rsplit(" ", 1)[1])
        readline(proc)  # flag path line
        yield pid, proc, flag
    finally:
        proc.kill()
        proc.wait()


def sensitive_status(diff):
    return {i["category"]: i["status"] for i in diff["items"] if i["severity"] in ("CRITICAL", "HIGH")}


def test_residue_test_against_a_real_process(demo):
    pid, proc, flag = demo
    before = run_scan(pid).as_dict(include_regions=False)
    assert {f["category"] for f in before["findings"]} >= {
        "AWS access key ID", "AWS secret access key", "Payment card number",
        "Password assignment", "JSON Web Token", "Bearer token", "Database connection string",
    }

    flag.touch()
    assert "logged out" in readline(proc)
    time.sleep(0.3)
    diff = diff_snapshots(before, run_scan(pid).as_dict(include_regions=False))

    status = sensitive_status(diff)
    for wiped in ("AWS access key ID", "AWS secret access key", "Payment card number"):
        assert status[wiped] == "wiped", wiped
    for leaked in ("JSON Web Token", "Bearer token", "Database connection string"):
        assert status[leaked] == "persisted", leaked
    assert diff["verdict"] == RESIDUE


def test_injection_style_anomalies_are_reported(demo):
    pid = demo[0]
    res = run_scan(pid)
    kinds = {a.kind.value for a in res.anomalies}
    assert {"RWX_REGION", "EMBEDDED_PE"} <= kinds
    assert any(a.severity == "CRITICAL" for a in res.anomalies)


def test_scan_covers_regions_and_reports_progress():
    seen = []
    res = run_scan(os.getpid(), on_update=lambda p: seen.append(p.done_bytes))
    assert res.committed_bytes > 0 and res.scanned_bytes > 0
    assert any(r.executable for r in res.regions)
    assert seen and seen[-1] >= seen[0]


def test_scan_of_missing_process_raises_cleanly():
    with pytest.raises((ProcessLookupError, PermissionError)):
        run_scan(0x7FFFFFF0)
