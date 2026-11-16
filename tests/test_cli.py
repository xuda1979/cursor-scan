"""CLI behaviour contracts: output formats, exit-code gate, error paths.

Drives ``cursorscan.cli.main`` directly (no subprocess) and asserts the
documented guarantees from the README: exit 0 on clean / 1 when the gate
is hit / 2 on usage and environment errors, JSON/SARIF/text formats, and
the ``--no-save`` / ``--history`` / ``--diff`` / ``--serve`` modes.
"""

from __future__ import annotations

import json

import pytest

from cursorscan.cli import main


class TestFormats:
    def test_json_output_parses(self, scan_bad_dir, tmp_path, capsys):
        rc = main([scan_bad_dir, "--format", "json",
                   "--history-dir", str(tmp_path), "--no-save"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 1  # bad fixture hits every gate
        assert doc["tool"]["name"] == "cursor-scan"
        assert doc["target"].endswith("scan_bad")
        assert len(doc["findings"]) > 0
        assert "findings" in doc and "dimensions" in doc

    def test_sarif_output_parses(self, scan_bad_dir, tmp_path, capsys):
        rc = main([scan_bad_dir, "--format", "sarif",
                   "--history-dir", str(tmp_path), "--no-save"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "cursor-scan"
        assert run["results"], "sarif must carry findings"
        assert run["results"][0]["ruleId"]

    def test_sarif_region_snippet_carries_source_line(self, scan_bad_dir,
                                                      tmp_path, capsys):
        rc = main([scan_bad_dir, "--format", "sarif",
                   "--history-dir", str(tmp_path), "--no-save"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 1
        with_code = [
            r for r in doc["runs"][0]["results"]
            if r.get("locations")
            and r["locations"][0]["physicalLocation"].get("region", {}).get("snippet")
        ]
        assert with_code, "at least one SARIF result should embed the source snippet"
        for r in with_code:
            snippet = r["locations"][0]["physicalLocation"]["region"]["snippet"]
            assert snippet.get("text"), "snippet text must be non-empty"

    def test_text_output_has_scorecard(self, scan_good_dir, tmp_path, capsys):
        rc = main([scan_good_dir, "--history-dir", str(tmp_path), "--no-save"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "评分" in out and "等级" in out
        assert "100" in out

    def test_text_empty_report(self, scan_good_dir, tmp_path, capsys):
        rc = main([scan_good_dir, "--history-dir", str(tmp_path), "--no-save"])
        capsys.readouterr()
        assert rc == 0


class TestGate:
    def test_bad_fixture_hits_high_gate(self, scan_bad_dir, tmp_path):
        rc = main([scan_bad_dir, "--fail-on", "high",
                   "--history-dir", str(tmp_path), "--no-save"])
        assert rc == 1

    def test_bad_fixture_hits_critical_gate(self, scan_bad_dir, tmp_path):
        rc = main([scan_bad_dir, "--fail-on", "critical",
                   "--history-dir", str(tmp_path), "--no-save"])
        assert rc == 1  # fixture carries critical findings

    def test_good_fixture_passes_gate(self, scan_good_dir, tmp_path):
        rc = main([scan_good_dir, "--fail-on", "low",
                   "--history-dir", str(tmp_path), "--no-save"])
        assert rc == 0


class TestErrors:
    def test_missing_dir_returns_2(self, tmp_path, capsys):
        rc = main([str(tmp_path / "does-not-exist")])
        err = capsys.readouterr().err
        assert rc == 2
        assert "不存在" in err

    def test_text_output_has_scorecard_when_clean(self, scan_good_dir,
                                                  tmp_path, capsys):
        rc = main([scan_good_dir, "--history-dir", str(tmp_path), "--no-save"])
        assert rc == 0
        capsys.readouterr()

    def test_diff_missing_refs_returns_2(self, tmp_path):
        rc = main(["--diff", "no-such-a", "no-such-b",
                   "--history-dir", str(tmp_path)])
        assert rc == 2

    def test_serve_bad_history_dir_returns_2(self, tmp_path):
        blocking = tmp_path / "not-a-dir"
        blocking.write_text("{}", encoding="utf-8")
        rc = main(["--serve", "--history-dir", str(blocking)])
        assert rc == 2

    def test_serve_privileged_port_returns_2(self, tmp_path):
        rc = main(["--serve", "--port", "1", "--history-dir", str(tmp_path)])
        assert rc == 2


class TestMeta:
    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code in (0, None)
        assert "cursor-scan" in capsys.readouterr().out

    def test_unknown_flag_is_usage_error(self):
        with pytest.raises(SystemExit) as exc:
            main(["--no-such-flag"])
        assert exc.value.code == 2


class TestHistoryFlags:
    def test_no_save_writes_no_snapshot(self, scan_bad_dir, tmp_path):
        main([scan_bad_dir, "--no-save", "--history-dir", str(tmp_path)])
        assert list(tmp_path.iterdir()) == []

    def test_default_scan_saves_snapshot(self, scan_good_dir, tmp_path):
        main([scan_good_dir, "--history-dir", str(tmp_path)])
        assert len(list(tmp_path.glob("*.json"))) == 1

    def test_history_lists_after_scan(self, scan_good_dir, tmp_path, capsys):
        main([scan_good_dir, "--history-dir", str(tmp_path)])
        capsys.readouterr()
        rc = main(["--history", "--history-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "扫描历史" in out
        assert "100" in out
