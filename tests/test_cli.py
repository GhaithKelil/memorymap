"""The command line is the whole interface, so test it directly (scans are faked; live ones are in test_live)."""

import json

import pytest

from conftest import finding, make_result
from memorymap import cli
from memorymap.diff import save_snapshot

SECRET = "AKIAIOSFODNN7EXAMPLE"
CARD = finding("4111111111111111", "credit_card", "Payment card number", "CRITICAL", 0x10100)


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def fake_scan(monkeypatch, *results):
    """Make scan_with_progress hand back the given results in order, for any target."""
    queue = list(results)
    monkeypatch.setattr(cli, "scan_with_progress", lambda pid, options: queue.pop(0))
    monkeypatch.setattr(cli, "resolve_target", lambda query: (1234, "demo.exe"))


def test_bare_command_prints_help_and_exits_cleanly(capsys):
    code, out = run(capsys)
    assert code == 0
    for command in ("scan", "residue", "snapshot", "diff", "list"):
        assert command in out


def test_there_is_no_dashboard_command(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["serve"])
    assert exc.value.code == 2


def test_list_prints_processes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "list_processes", lambda: [
        {"pid": 42, "name": "alpha.exe", "rss_mb": 12.5, "username": "me"},
        {"pid": 43, "name": "beta.exe", "rss_mb": 3.0, "username": "me"},
    ])
    code, out = run(capsys, "list", "-f", "alpha")
    assert code == 0 and "alpha.exe" in out and "beta.exe" not in out


def test_scan_masks_secrets_unless_revealed(monkeypatch, capsys):
    fake_scan(monkeypatch, make_result([finding()]), make_result([finding()]))
    _, masked = run(capsys, "scan", "1")
    assert SECRET not in masked and "AWS access key ID" in masked
    _, shown = run(capsys, "scan", "1", "--reveal")
    assert SECRET in shown


def test_scan_writes_json_and_html_without_plaintext(monkeypatch, capsys, tmp_path):
    fake_scan(monkeypatch, make_result([finding()]))
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    code, _ = run(capsys, "scan", "1", "--json", str(j), "--html", str(h))
    assert code == 0
    assert json.loads(j.read_text())["counts"]["findings"] == 1
    assert SECRET not in j.read_text() and SECRET not in h.read_text()


@pytest.mark.parametrize("level,expected", [("critical", 2), ("high", 2), ("low", 2)])
def test_fail_on_exits_2_when_the_threshold_is_met(monkeypatch, capsys, level, expected):
    fake_scan(monkeypatch, make_result([finding()]))  # one CRITICAL finding
    assert run(capsys, "scan", "1", "--fail-on", level)[0] == expected


def test_fail_on_exits_0_when_nothing_reaches_the_threshold(monkeypatch, capsys):
    fake_scan(monkeypatch, make_result([finding("https://example.com/x/y", "url", "URL", "LOW")]))
    assert run(capsys, "scan", "1", "--fail-on", "high")[0] == 0


def test_residue_reports_wiped_secrets_as_clean(monkeypatch, capsys):
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: None)
    fake_scan(monkeypatch, make_result([finding(), CARD]), make_result([]))
    code, out = run(capsys, "residue", "1", "--action", "log out")
    assert code == 0 and "CLEAN" in out and "2 wiped" in out


def test_residue_exits_1_when_secrets_survive(monkeypatch, capsys):
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: None)
    fake_scan(monkeypatch, make_result([finding(), CARD]), make_result([CARD]))
    code, out = run(capsys, "residue", "1", "--action", "log out")
    assert code == 1 and "RESIDUE" in out and "1 still present" in out


def test_residue_exits_3_when_the_baseline_had_nothing(monkeypatch, capsys):
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: None)
    fake_scan(monkeypatch, make_result([]), make_result([finding()]))
    code, out = run(capsys, "residue", "1", "--action", "log out")
    assert code == 3 and "INCONCLUSIVE" in out


def test_snapshot_then_diff_round_trip(monkeypatch, capsys, tmp_path):
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    fake_scan(monkeypatch, make_result([finding(), CARD]), make_result([CARD]))
    assert run(capsys, "snapshot", "1", "-o", str(before))[0] == 0
    assert run(capsys, "snapshot", "1", "-o", str(after))[0] == 0
    assert SECRET not in before.read_text()  # snapshots never hold plaintext
    code, out = run(capsys, "diff", str(before), str(after))
    assert code == 1 and "1 wiped" in out and "1 still present" in out


def test_diff_rejects_a_file_that_is_not_a_snapshot(capsys, tmp_path):
    bogus = tmp_path / "x.json"
    bogus.write_text("{}")
    save_snapshot(make_result([finding()]), str(tmp_path / "ok.json"))
    code, out = run(capsys, "diff", str(bogus), str(tmp_path / "ok.json"))
    assert code == 64 and "not a MemoryMap snapshot" in out


def test_unknown_process_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "find_processes", lambda q: [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "nosuchprocess"])
    assert exc.value.code == 64
    assert "No process matches" in capsys.readouterr().err
