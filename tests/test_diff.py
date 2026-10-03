import json

import pytest

from conftest import finding, make_result
from memorymap.diff import (CLEAN, INCONCLUSIVE, MINOR, RESIDUE, diff_snapshots, load_snapshot, save_snapshot)

AWS = finding()
CARD = finding("4111111111111111", "credit_card", "Payment card number", "CRITICAL", 0x10100)
EMAIL = finding("a@example.com", "email", "Email address", "MEDIUM", 0x10200)
URL = finding("https://example.com/x/y", "url", "URL", "LOW", 0x10300)
URL.sensitive = False


def snap(*findings):
    return make_result(findings).as_dict(include_regions=False)


def statuses(d):
    return {i["category"]: i["status"] for i in d["items"]}


def test_classifies_persisted_wiped_and_new():
    d = diff_snapshots(snap(AWS, CARD), snap(CARD, EMAIL))
    assert statuses(d) == {"Payment card number": "persisted", "AWS access key ID": "wiped", "Email address": "new"}
    assert d["counts"] == {"persisted": 1, "new": 1, "wiped": 1}


def test_verdicts():
    assert diff_snapshots(snap(AWS), snap(AWS))["verdict"] == RESIDUE
    assert diff_snapshots(snap(AWS, EMAIL), snap(EMAIL))["verdict"] == MINOR
    assert diff_snapshots(snap(AWS), snap())["verdict"] == CLEAN
    assert diff_snapshots(snap(), snap(AWS))["verdict"] == INCONCLUSIVE


def test_non_sensitive_findings_are_ignored():
    assert diff_snapshots(snap(URL), snap(URL))["items"] == []


def test_low_severity_module_data_is_ignored_but_high_severity_is_not():
    in_module = lambda f, where: {**f, "where": where}  # noqa: E731
    a, b = snap(EMAIL, AWS), snap(EMAIL, AWS)
    for s in (a, b):
        s["findings"] = [in_module(f, "Module python311.dll") for f in s["findings"]]
    d = diff_snapshots(a, b)
    assert [i["category"] for i in d["items"]] == ["AWS access key ID"]


def test_new_secrets_alone_are_not_residue():
    assert diff_snapshots(snap(EMAIL), snap(EMAIL, AWS))["verdict"] == MINOR


def test_copy_counts_are_compared():
    more = finding(count=5)
    d = diff_snapshots(snap(finding(count=2)), snap(more))
    item = d["items"][0]
    assert (item["before"]["count"], item["after"]["count"]) == (2, 5)


def test_findings_are_attributed_to_a_region():
    d = diff_snapshots(snap(finding(address=0x10010)), snap(finding(address=0x10010)))
    assert d["items"][0]["after"]["where"] == "Private memory (heap/stack)"
    res = make_result()
    assert res.where(0x7FF000000010) == "Module demo.dll"
    assert res.where(0x1) == "unknown"


def test_snapshot_file_has_no_plaintext(tmp_path):
    path = tmp_path / "s.json"
    save_snapshot(make_result([AWS, CARD]), str(path))
    text = path.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in text and "4111111111111111" not in text
    assert json.loads(text)["format"] == "memorymap-snapshot/1"
    assert diff_snapshots(load_snapshot(str(path)), load_snapshot(str(path)))["verdict"] == RESIDUE


def test_load_rejects_other_json(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("{}")
    with pytest.raises(ValueError):
        load_snapshot(str(path))
