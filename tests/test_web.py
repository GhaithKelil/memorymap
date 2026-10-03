from conftest import finding, make_result
from memorymap.anomaly import Anomaly, Kind
from memorymap.report import render_report
from memorymap.web.app import ScanManager, Snapshot, create_app


def client_with(*results):
    mgr = ScanManager()
    for i, res in enumerate(results, 1):
        mgr.snapshots.append(Snapshot(i, f"#{i}", res))
    mgr.state = "done"
    return create_app(mgr).test_client(), mgr


ANOM = Anomaly(Kind.RWX_REGION, "HIGH", 0x10000, 0x1000, "Private", "RWX", "<script>alert(1)</script>")


def test_dashboard_and_assets_are_served():
    c, _ = client_with()
    assert b"MemoryMap" in c.get("/").data
    assert c.get("/static/app.js").status_code == 200
    assert "default-src 'self'" in c.get("/").headers["Content-Security-Policy"]


def test_foreign_host_header_is_rejected():
    c, _ = client_with()
    assert c.get("/api/status", headers={"Host": "evil.example"}).status_code == 403
    assert c.get("/api/status", headers={"Host": "localhost:5000"}).status_code == 200


def test_result_is_masked_by_default():
    c, _ = client_with(make_result([finding()]))
    body = c.get("/api/result").get_json()
    assert "AKIAIOSFODNN7EXAMPLE" not in str(body) and body["findings"][0]["where"]


def test_result_404_before_any_scan():
    c, _ = client_with()
    assert c.get("/api/result").status_code == 404


def test_scan_endpoint_validates_input():
    c, _ = client_with()
    assert c.post("/api/scan", json={"pid": "abc"}).status_code == 400
    assert c.post("/api/scan", data="pid=1").status_code == 400


def test_diff_endpoint_defaults_to_last_two_snapshots():
    c, _ = client_with(make_result([finding()]), make_result([]))
    d = c.get("/api/diff").get_json()
    assert d["verdict"] == "CLEAN" and d["counts"]["wiped"] == 1 and d["verdict_text"]


def test_diff_needs_two_snapshots():
    c, _ = client_with(make_result([]))
    assert c.get("/api/diff").status_code == 404


def test_exports():
    c, _ = client_with(make_result([finding()], [ANOM]))
    assert c.get("/export.json").mimetype == "application/json"
    html = c.get("/export.html").get_data(as_text=True)
    assert "demo.exe" in html and "AKIAIOSFODNN7EXAMPLE" not in html
    assert c.get("/export.pdf").status_code == 404


def test_report_escapes_memory_contents():
    html = render_report(make_result([], [ANOM]))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_report_reveal_shows_values():
    assert "AKIAIOSFODNN7EXAMPLE" in render_report(make_result([finding()]), reveal=True)
