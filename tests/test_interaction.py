"""Backend support for the inspector, lifetime matrix and live feed."""

from conftest import finding, make_result
from memorymap.diff import timeline
from memorymap.scan import Progress
from memorymap.scanner import SecretScanner
from memorymap.web.app import ScanManager, Snapshot, create_app

AWS = finding()
CARD = finding("4111111111111111", "credit_card", "Payment card number", "CRITICAL", 0x10100)
JWT = finding("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "jwt", "JSON Web Token", "HIGH", 0x10200)


def snap(*findings):
    return make_result(findings).as_dict(include_regions=False)


def test_timeline_tracks_presence_across_snapshots():
    t = timeline([snap(AWS, CARD, JWT), snap(CARD, JWT), snap(JWT)])
    cells = {r["category"]: [c is not None for c in r["cells"]] for r in t["rows"]}
    assert cells["AWS access key ID"] == [True, False, False]
    assert cells["Payment card number"] == [True, True, False]
    assert cells["JSON Web Token"] == [True, True, True]
    assert [r["severity"] for r in t["rows"]] == ["CRITICAL", "CRITICAL", "HIGH"]  # worst first


def test_timeline_endpoint_needs_two_snapshots():
    mgr = ScanManager()
    mgr.snapshots.append(Snapshot(1, "#1", make_result([AWS])))
    client = create_app(mgr).test_client()
    assert client.get("/api/timeline").status_code == 404
    mgr.snapshots.append(Snapshot(2, "#2", make_result([])))
    body = client.get("/api/timeline").get_json()
    assert [s["id"] for s in body["snapshots"]] == [1, 2] and body["rows"]


def test_peek_rejects_bad_input_and_unmapped_addresses():
    mgr = ScanManager()
    mgr.snapshots.append(Snapshot(1, "#1", make_result([AWS])))
    client = create_app(mgr).test_client()
    assert client.get("/api/peek").status_code == 400
    assert client.get("/api/peek?id=1&address=1").status_code == 404  # not inside any region


def test_scanner_feed_reports_only_new_findings():
    scanner = SecretScanner()
    first = scanner.feed(b"AKIAIOSFODNN7EXAMPLE and 4111111111111111 ", 0)
    assert {f.pattern for f in first} == {"aws_access_key", "credit_card"}
    again = scanner.feed(b"AKIAIOSFODNN7EXAMPLE ", 0x1000)
    assert again == [] and scanner.findings()[0].count >= 1  # a repeat is counted, not re-announced


def test_progress_feed_is_ordered_and_capped():
    p = Progress()
    for i in range(130):
        p.push("HIGH", "x", str(i))
    assert len(p.feed) == 100
    assert [e["seq"] for e in p.feed] == sorted(e["seq"] for e in p.feed)
    assert p.feed[-1]["seq"] == 130


def test_status_includes_the_feed():
    mgr = ScanManager()
    mgr.progress.push("CRITICAL", "AWS access key ID", "AKIA••••")
    body = create_app(mgr).test_client().get("/api/status").get_json()
    assert body["feed"][-1]["label"] == "AWS access key ID"
