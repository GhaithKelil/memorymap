from conftest import finding, make_result
from memorymap.anomaly import Anomaly, Kind
from memorymap.report import render_report

ANOMALY = Anomaly(Kind.RWX_REGION, "HIGH", 0x10000, 0x1000, "Private", "RWX", "<script>alert(1)</script>")


def test_report_escapes_memory_contents():
    html = render_report(make_result([], [ANOMALY]))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_report_masks_values_by_default():
    html = render_report(make_result([finding()]))
    assert "demo.exe" in html and "AKIAIOSFODNN7EXAMPLE" not in html


def test_report_reveal_shows_values():
    assert "AKIAIOSFODNN7EXAMPLE" in render_report(make_result([finding()]), reveal=True)


def test_report_says_when_a_pattern_was_capped():
    res = make_result([finding()])
    res.capped = {"email": 2000}
    assert "Capped at 2000" in render_report(res)
