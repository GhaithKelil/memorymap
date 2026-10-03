"""Bounded memory and unchanged results on text-heavy input, and one summary for random-data regions."""

import base64
import json
import os

from conftest import make_result, region
from memorymap.anomaly import AnomalyDetector, Kind
from memorymap.scanner import PREFILTER, SecretScanner


def text_blob(n: int, start: int = 0) -> bytes:
    """n lines, every email and URL unique, like a process full of logs or web content."""
    return "\n".join(f"user{i:09d}@example.com visited https://example.com/p/{i:09d}"
                     for i in range(start, start + n)).encode()


def test_low_and_medium_patterns_are_capped_and_reported():
    s = SecretScanner(caps={"LOW": 50, "MEDIUM": 50})
    s.feed(text_blob(500), 0)
    kinds = [f.pattern for f in s.findings()]
    assert kinds.count("email") == 50 and kinds.count("url") == 50
    assert s.capped == {"email": 50, "url": 50}


def test_a_full_pattern_stops_growing_across_chunks():
    s = SecretScanner(caps={"LOW": 20, "MEDIUM": 20})
    s.feed(text_blob(200), 0)
    before = len(s)
    s.feed(text_blob(5000, start=1000), 0x10000)
    assert len(s) == before


def test_high_severity_stops_storing_but_keeps_counting_known_values():
    s = SecretScanner(caps={"HIGH": 3})
    s.feed(b"\n".join(b"password = Value%03dxyz!" % i for i in range(10)), 0)
    stored = [f for f in s.findings() if f.pattern == "password_assignment"]
    assert len(stored) == 3 and "password_assignment" in s.capped
    s.feed(b"password = Value000xyz! and again password = Value000xyz!", 0x1000)
    assert next(f for f in s.findings() if f.value == "Value000xyz!").count == 3


def test_critical_findings_survive_a_flood_of_noise():
    key = b"AKIA" + b"QWERTYUIOPASDFGH"  # assembled so the source holds no key-shaped literal
    s = SecretScanner()
    s.feed(text_blob(6000) + b"\n" + key + b"\n", 0)
    assert any(f.pattern == "aws_access_key" for f in s.findings())
    assert len(s) < 4100  # bounded: two capped patterns at 2000, plus the single critical finding


def test_prefilter_changes_speed_not_results():
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")

    corpus = b"\n".join([
        b"AKIA" + b"QWERTYUIOPASDFGH",
        b"aws_secret_access_key = " + b"wJalrXUtnFEMI" + b"/K7MDENG/bPxRfiCYEXAMPLEKEY",
        b"card=4111111111111111",
        seg({"alg": "HS256"}) + b"." + seg({"sub": "1"}) + b".c2lnbmF0dXJlLWJ5dGVz",
        b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
        b"password = Tr0ub4dor&3xample",
        b"postgresql://admin:Sup3rS3cretPass@db.internal.example:5432/prod",
        b"https://user:hunter2pass@host.example/path",
        b"contact jane.doe@example.com or 123-45-6789",
        b"pay 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        b"wallet 0x" + b"ab" * 20,
        b"see https://example.com/some/long/path and 10.0.0.1:8080 and /api/v2/users/export",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"gh" + b"p_" + b"A" * 36,
        b"xox" + b"b-123456789012",
        b"sk_" + b"live_" + b"A" * 24,
    ])
    fast = SecretScanner(prefilter=True).scan(corpus)
    slow = SecretScanner(prefilter=False).scan(corpus)
    as_set = lambda found: {(f.pattern, f.value, f.count) for f in found}  # noqa: E731
    assert as_set(fast) == as_set(slow)
    assert len({f.pattern for f in fast}) >= 12
    assert {f.pattern for f in fast} >= {p for p in PREFILTER if p in {"jwt", "email", "url", "bearer_token"}}


def test_detector_prefilter_still_catches_mixed_case_strings_and_nop_sleds():
    det = AnomalyDetector()
    det.begin(region())
    det.feed(b"\x90" * 40 + b" WRITEPROCESSMEMORY createRemoteThread")
    found = {a.kind: a for a in det.end()}
    assert Kind.SUSPICIOUS_STRINGS in found
    assert "nop sled" in found[Kind.SUSPICIOUS_STRINGS].detail


def test_random_data_regions_are_reported_once():
    det = AnomalyDetector()
    for i in range(5):
        det.begin(region(base=0x100000 + i * 0x20000, size=65536, protect="RW"))
        det.feed(os.urandom(65536))
        assert det.end() == []  # nothing per region
    det.finalize()
    assert len(det.anomalies) == 1
    only = det.anomalies[0]
    assert only.kind == Kind.HIGH_ENTROPY and only.severity == "LOW" and "5 data regions" in only.detail


def test_executable_random_regions_still_report_individually():
    det = AnomalyDetector()
    det.begin(region(protect="RX", size=65536))
    det.feed(os.urandom(65536))
    assert any(a.kind == Kind.HIGH_ENTROPY and a.severity == "HIGH" for a in det.end())


def test_result_reports_what_was_capped():
    res = make_result()
    res.capped = {"email": 2000}
    body = res.as_dict()
    assert body["capped"] == [{"pattern": "email", "category": "Email address", "cap": 2000}]
