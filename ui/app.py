import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, send_file, abort
from core.reader import list_processes, ProcessMemoryReader
from core.scanner import SecretScanner
from core.analyzer import build_report
from core.anomaly import AnomalyDetector, anomaly_summary
from reports.generator import generate_report

app = Flask(__name__)

_report      = None
_regions     = None
_pid         = None
_proc_name   = None
_anomaly_sum = None


def run_scan(pid: int):
    global _report, _regions, _pid, _proc_name, _anomaly_sum

    procs      = list_processes()
    proc       = next((p for p in procs if p["pid"] == pid), None)
    _proc_name = proc["name"] if proc else f"PID {pid}"
    _pid       = pid

    with ProcessMemoryReader(pid) as reader:
        _regions = reader.enumerate_regions(read_data=True)

    committed = [r for r in _regions if r.state == "COMMIT"]
    total_mb  = sum(r.size for r in committed) / (1024 * 1024)

    scanner  = SecretScanner(min_severity="LOW")
    findings = scanner.scan_regions(committed)
    _report  = build_report(
        pid=pid,
        process_name=_proc_name,
        total_regions=len(_regions),
        committed_mb=total_mb,
        findings=findings,
    )

    detector     = AnomalyDetector()
    anomalies    = detector.detect(committed)
    _anomaly_sum = anomaly_summary(anomalies)

    print(f"[MemoryMap] Scan done — {len(findings)} findings, {len(anomalies)} anomalies, risk {_report.risk_score}/100")


@app.route("/")
def index():
    return render_template("dashboard.html", proc_name=_proc_name, pid=_pid)


@app.route("/api/report")
def api_report():
    if _report is None:
        return jsonify({"error": "No scan data"}), 404
    return jsonify(_report.as_dict())


@app.route("/api/regions")
def api_regions():
    if _regions is None:
        return jsonify({"error": "No region data"}), 404
    committed = [r for r in _regions if r.state == "COMMIT"]
    data = [{
        "base":       f"0x{r.base_address:016X}",
        "size_kb":    round(r.size / 1024, 1),
        "protect":    r.protect,
        "type":       r.region_type,
        "executable": r.is_executable,
        "writable":   r.is_writable,
    } for r in committed]
    return jsonify(data)


@app.route("/api/processes")
def api_processes():
    return jsonify(list_processes()[:50])


@app.route("/api/anomalies")
def api_anomalies():
    if _anomaly_sum is None:
        return jsonify({"error": "No anomaly data"}), 404
    return jsonify(_anomaly_sum)


@app.route("/export")
def export_report():
    if _report is None or _regions is None:
        abort(404, "No scan data available.")

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir   = os.path.join(project_root, "reports", "output")

    report_path = generate_report(
        report    = _report,
        anomalies = _anomaly_sum or {"total": 0, "items": []},
        regions   = _regions,
        output_dir= output_dir,
    )
    print(f"[MemoryMap] Report: {report_path}")
    return send_file(
        report_path,
        as_attachment=True,
        download_name=os.path.basename(report_path),
        mimetype="text/html",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid",  type=int, required=True)
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print(f"[MemoryMap] Scanning PID {args.pid}...")
    try:
        run_scan(args.pid)
    except PermissionError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print(f"[MemoryMap] Ready → http://localhost:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False)
