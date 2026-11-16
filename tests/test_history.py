"""Tests for scan history persistence, snapshot resolution and diffing (AC4)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from cursorscan.history import (diff_snapshots, list_history,
                                resolve_snapshot, save_snapshot,
                                slug_for_target, snapshot_path)
from cursorscan.models import Evidence, ScanResult
from cursorscan.scan import ScanOptions, scan_project


def _result(score: int = 80, grade: str = "B") -> ScanResult:
    r = ScanResult(target="/tmp/proj", score=score, grade=grade)
    r.scanned_files = 3
    r.skipped_files = 1
    return r


class TestSnapshots:
    def test_slug_for_target(self):
        assert slug_for_target("/a/b/My_Proj!") == "my_proj"
        assert slug_for_target("/") == "root"
        assert slug_for_target("???") == "project"

    def test_snapshot_path_same_second_is_unique(self, tmp_path):
        now = datetime.now(timezone.utc)
        p1 = snapshot_path("proj", str(tmp_path), now)
        open(p1, "w").close()  # simulate the first save landing on disk
        p2 = snapshot_path("proj", str(tmp_path), now)
        assert p1 != p2
        assert p1.endswith(".json") and p2.endswith(".json")

    def test_save_and_load_roundtrip(self, tmp_path):
        r = _result()
        path = save_snapshot(r, str(tmp_path))
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc["score"] == 80
        assert doc["grade"] == "B"
        assert doc["target"] == "/tmp/proj"
        assert doc["findings"] == []

    def test_save_creates_history_dir(self, tmp_path):
        hd = tmp_path / "nested" / "hist"
        save_snapshot(_result(), str(hd))
        assert hd.is_dir()


class TestListAndResolve:
    def test_list_history_newest_first(self, tmp_path):
        hd = str(tmp_path)
        save_snapshot(_result(score=50, grade="D"), hd)
        save_snapshot(_result(score=100, grade="A"), hd)
        entries = list_history(hd)
        assert len(entries) == 2
        # newest-first: the second write sorts above the first by filename
        assert entries[0].score == 100
        assert entries[0].grade == "A"

    def test_list_history_skips_malformed(self, tmp_path):
        (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
        save_snapshot(_result(), str(tmp_path))
        assert len(list_history(str(tmp_path))) == 1

    def test_resolve_snapshot_by_slug(self, tmp_path):
        hd = str(tmp_path)
        path = save_snapshot(_result(), hd)
        slug = slug_for_target("/tmp/proj")
        assert resolve_snapshot(slug, hd) == path

    def test_resolve_snapshot_by_path(self, tmp_path):
        p = save_snapshot(_result(), str(tmp_path))
        assert resolve_snapshot(p, str(tmp_path)) == p

    def test_resolve_snapshot_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            resolve_snapshot("nope", str(tmp_path))


def _finding(rule_id: str, file: str, line: int) -> dict:
    return {"rule_id": rule_id, "file": file, "line": line,
            "severity": "high", "message": "m", "title": "t", "fix": "f"}


class TestDiffing:
    def setup_method(self):
        self.before = {"score": 60, "grade": "C",
                       "findings": [_finding("a", "x.py", 1),
                                    _finding("b", "x.py", 2)]}
        self.after = {"score": 80, "grade": "B",
                      "findings": [_finding("a", "x.py", 1),   # kept
                                   _finding("c", "x.py", 3)]}  # added

    def test_added_fixed_kept_partition(self):
        diff = diff_snapshots(self.before, self.after)
        assert [f["rule_id"] for f in diff.added] == ["c"]
        assert [f["rule_id"] for f in diff.fixed] == ["b"]
        assert [f["rule_id"] for f in diff.kept] == ["a"]

    def test_score_delta(self):
        assert diff_snapshots(self.before, self.after).score_delta == 20

    def test_path_normalization_dedupes(self):
        b = {"findings": [_finding("a", "x.py", 1)]}
        a = {"findings": [_finding("a", "./x.py", 1)]}  # same file, diff path form
        assert diff_snapshots(b, a).kept


class TestCliHistory:
    def test_cli_diff_reports_changes(self, scan_bad_dir, scan_good_dir,
                                      tmp_path, capsys):
        from cursorscan.cli import main
        hd = str(tmp_path)
        main([scan_bad_dir, "--history-dir", hd, "--format", "json"])
        main([scan_good_dir, "--history-dir", hd, "--format", "json"])
        from cursorscan.history import list_history
        entries = list_history(hd)
        assert len(entries) == 2
        rc = main(["--diff", scan_bad_dir, scan_good_dir, "--history-dir", hd])
        assert rc == 0
        diff_out = capsys.readouterr().out
        assert "评分" in diff_out
        assert "新增" in diff_out or "修复" in diff_out

    def test_history_empty_returns_one(self, tmp_path):
        from cursorscan.cli import main
        assert main(["--history", "--history-dir", str(tmp_path / "none")]) == 1

    def test_history_lists_snapshots(self, scan_bad_dir, tmp_path, capsys):
        from cursorscan.cli import main
        hd = str(tmp_path)
        main([scan_bad_dir, "--history-dir", hd, "--format", "json"])
        rc = main(["--history", "--history-dir", hd])
        assert rc == 0
        assert "扫描历史" in capsys.readouterr().out
