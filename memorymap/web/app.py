"""Local web dashboard: process picker, live scan progress, results and residue diffs."""

from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from flask import Flask, Response, abort, jsonify, render_template, request

from memorymap import __version__
from memorymap.diff import VERDICT_TEXT, diff_snapshots, timeline
from memorymap.reader import ProcessMemoryReader, is_admin, list_processes
from memorymap.scan import Progress, ScanCancelled, ScanOptions, ScanResult, run_scan

LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
MAX_SNAPSHOTS = 12
PEEK_MAX = 1024


@dataclass
class Snapshot:
    id: int
    label: str
    result: ScanResult

    def meta(self) -> dict:
        r = self.result
        return {
            "id": self.id, "label": self.label, "pid": r.pid, "process_name": r.process_name,
            "taken_at": r.started_at.isoformat(timespec="seconds"), "score": r.score, "risk": r.label,
            "findings": len(r.findings), "anomalies": len(r.anomalies),
            "by_severity": r.severity_counts(),
        }


class ScanManager:
    """Runs one scan at a time on a background thread and keeps snapshots of the target.

    Snapshots live in memory only; they are never written to disk by the dashboard.
    """

    def __init__(self, options: Optional[ScanOptions] = None, reveal: bool = False):
        self.options = options or ScanOptions()
        self.reveal = reveal
        self.state = "idle"  # idle | scanning | done | error | cancelled
        self.error = ""
        self.pid: Optional[int] = None
        self.progress = Progress()
        self.snapshots: List[Snapshot] = []
        self._next_id = 1
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    @property
    def result(self) -> Optional[ScanResult]:
        return self.snapshots[-1].result if self.snapshots else None

    def snapshot(self, snap_id: Optional[int]) -> Optional[Snapshot]:
        if snap_id is None:
            return self.snapshots[-1] if self.snapshots else None
        return next((s for s in self.snapshots if s.id == snap_id), None)

    def start(self, pid: int) -> None:
        with self._lock:
            if self.state == "scanning":
                raise RuntimeError("A scan is already running.")
            if self.snapshots and self.snapshots[-1].result.pid != pid:
                self.snapshots.clear()
            self.state, self.error, self.pid = "scanning", "", pid
            self.progress = Progress()
            self._cancel = threading.Event()
        threading.Thread(target=self._run, args=(pid, self.progress, self._cancel), daemon=True).start()

    def _run(self, pid: int, progress: Progress, cancel: threading.Event) -> None:
        try:
            result = run_scan(pid, self.options, progress, cancel)
        except ScanCancelled:
            self.state = "cancelled"
        except Exception as exc:  # surfaced to the UI rather than killing the thread silently
            self.state, self.error = "error", str(exc)
        else:
            with self._lock:
                label = f"#{self._next_id} · {datetime.now().strftime('%H:%M:%S')}"
                self.snapshots.append(Snapshot(self._next_id, label, result))
                self._next_id += 1
                del self.snapshots[:-MAX_SNAPSHOTS]
                self.state = "done"

    def cancel(self) -> None:
        self._cancel.set()

    def reset(self) -> None:
        with self._lock:
            if self.state != "scanning":
                self.snapshots.clear()
                self.state, self.pid = "idle", None

    def status(self) -> dict:
        p = self.progress
        return {
            "state": self.state,
            "error": self.error,
            "pid": self.pid,
            "progress": {
                "phase": p.phase, "fraction": round(p.fraction, 4),
                "done_bytes": p.done_bytes, "total_bytes": p.total_bytes,
                "findings": p.findings, "anomalies": p.anomalies,
            },
            "feed": p.feed[-14:],
            "snapshots": [s.meta() for s in self.snapshots],
        }


def create_app(manager: Optional[ScanManager] = None, allow_remote: bool = False) -> Flask:
    app = Flask(__name__)
    mgr = manager or ScanManager()
    app.config["manager"] = mgr

    @app.before_request
    def _guard_host():
        # Defends against DNS rebinding: only answer requests addressed to a loopback name.
        if not allow_remote and request.host.rsplit(":", 1)[0] not in LOCAL_HOSTS:
            abort(403)

    @app.after_request
    def _headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        )
        return resp

    @app.get("/")
    def index():
        return render_template("dashboard.html", version=__version__)

    @app.get("/api/info")
    def info():
        return jsonify(version=__version__, admin=is_admin(), reveal=mgr.reveal)

    @app.get("/api/processes")
    def processes():
        return jsonify(list_processes())

    @app.get("/api/status")
    def status():
        return jsonify(mgr.status())

    @app.post("/api/scan")
    def scan():
        body = request.get_json(silent=True) or {}
        try:
            pid = int(body["pid"])
        except (KeyError, TypeError, ValueError):
            return jsonify(error="Body must be JSON with an integer 'pid'."), 400
        try:
            mgr.start(pid)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 409
        return jsonify(mgr.status()), 202

    @app.post("/api/cancel")
    def cancel():
        mgr.cancel()
        return jsonify(mgr.status())

    @app.post("/api/reset")
    def reset():
        mgr.reset()
        return jsonify(mgr.status())

    @app.get("/api/result")
    def result():
        snap = mgr.snapshot(request.args.get("id", type=int))
        if snap is None:
            return jsonify(error="No scan result yet."), 404
        return jsonify(snap.result.as_dict(reveal=mgr.reveal))

    @app.delete("/api/snapshots/<int:snap_id>")
    def delete_snapshot(snap_id: int):
        mgr.snapshots[:] = [s for s in mgr.snapshots if s.id != snap_id]
        return jsonify(mgr.status())

    @app.get("/api/diff")
    def diff():
        after = mgr.snapshot(request.args.get("after", type=int))
        before = mgr.snapshot(request.args.get("before", type=int)) if request.args.get("before") else (
            mgr.snapshots[-2] if len(mgr.snapshots) > 1 else None)
        if before is None or after is None:
            return jsonify(error="Take at least two snapshots to compare."), 404
        dump = lambda s: s.result.as_dict(reveal=mgr.reveal, include_regions=False)  # noqa: E731
        out = diff_snapshots(dump(before), dump(after))
        out["verdict_text"] = VERDICT_TEXT[out["verdict"]]
        return jsonify(out)

    @app.get("/api/timeline")
    def timeline_view():
        if len(mgr.snapshots) < 2:
            return jsonify(error="Take at least two snapshots to see a timeline."), 404
        dumps = [s.result.as_dict(reveal=mgr.reveal, include_regions=False) for s in mgr.snapshots]
        out = timeline(dumps)
        for meta, snap in zip(out["snapshots"], mgr.snapshots):
            meta["id"], meta["label"] = snap.id, snap.label
        return jsonify(out)

    @app.get("/api/peek")
    def peek():
        """Hex view of live memory around an address. Bytes covered by sensitive findings are
        redacted unless the server was started with --reveal."""
        snap = mgr.snapshot(request.args.get("id", type=int))
        address = request.args.get("address", type=int)
        length = min(max(request.args.get("length", 256, type=int), 16), PEEK_MAX)
        if snap is None or address is None:
            return jsonify(error="Needs a snapshot and an address."), 400
        res = snap.result
        region = res.region_at(address)
        if region is None or not region.readable:
            return jsonify(error="That address is not in a readable region of this snapshot."), 404
        start = max(region.base, (address - 64) & ~0xF)
        end = min(region.end, start + length)
        try:
            with ProcessMemoryReader(res.pid) as reader:
                data = bytearray(reader.read(start, end - start))
        except ProcessLookupError:
            return jsonify(error="The process is no longer running."), 410
        except (PermissionError, OSError) as exc:
            return jsonify(error=str(exc)), 403

        marks = []
        for f in res.findings:
            width = len(f.value) * (2 if f.encoding == "utf-16" else 1)
            lo, hi = max(f.address, start), min(f.address + width, end)
            if lo >= hi:
                continue
            redact = f.sensitive and not mgr.reveal
            marks.append({"start": lo - start, "end": hi - start, "severity": f.severity,
                          "category": f.category, "redacted": redact})
        shown: list = list(data)
        for m in marks:
            if m["redacted"]:
                shown[m["start"]:m["end"]] = [None] * (m["end"] - m["start"])
        return jsonify(start=start, bytes=shown, marks=marks, region={
            "base": region.base, "size": region.size, "protect": region.protect, "kind": region.kind,
            "file": region.mapped_file, "where": res.where(address)})

    @app.get("/export.<fmt>")
    def export(fmt: str):
        snap = mgr.snapshot(request.args.get("id", type=int))
        if snap is None:
            abort(404)
        res = snap.result
        stem = f"memorymap_{res.process_name}_{res.pid}"
        if fmt == "json":
            body, mime = json.dumps(res.as_dict(reveal=mgr.reveal), indent=2), "application/json"
        elif fmt == "html":
            from memorymap.report import render_report
            body, mime = render_report(res, reveal=mgr.reveal), "text/html"
        else:
            abort(404)
        return Response(body, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{stem}.{fmt}"'})

    return app


def serve(pid: Optional[int] = None, host: str = "127.0.0.1", port: int = 5000,
          open_browser: bool = True, reveal: bool = False, options: Optional[ScanOptions] = None) -> None:
    mgr = ScanManager(options, reveal)
    app = create_app(mgr, allow_remote=host not in LOCAL_HOSTS)
    if pid is not None:
        mgr.start(pid)
    url = f"http://{'localhost' if host in LOCAL_HOSTS else host}:{port}"
    print(f"MemoryMap dashboard at {url}  (Ctrl+C to stop)")
    if host not in LOCAL_HOSTS:
        print("WARNING: bound to a non-loopback address. Anyone who can reach it can read scan results.")
    if open_browser:
        threading.Timer(0.8, webbrowser.open, args=(url,)).start()
    app.run(host=host, port=port, threaded=True)
