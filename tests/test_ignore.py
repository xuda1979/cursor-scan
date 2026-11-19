"""Tests for finding suppression via --ignore / .cursor-scan.json."""

from __future__ import annotations

import json
import os
import shutil

import pytest

from cursorscan.cli import main
from cursorscan.ignore import IgnorePattern, compile_ignores


class TestIgnorePatternParse:
    def test_single_glob_form(self):
        p = IgnorePattern.parse("secrets.*")
        assert p.rule == "secrets.*"
        assert p.file is None
        assert p.line is None

    def test_rule_file_form(self):
        p = IgnorePattern.parse("injection.sql_concat:app.py")
        assert p.rule == "injection.sql_concat"
        assert p.file == "app.py"
        assert p.line is None

    def test_rule_file_line_form(self):
        p = IgnorePattern.parse("injection.sql_concat:app.py:11")
        assert p.rule == "injection.sql_concat"
        assert p.file == "app.py"
        assert p.line == 11

    def test_line_part_ignored_when_not_numeric(self):
        p = IgnorePattern.parse("injection.sql_concat:app.py:abc")
        assert p.line is None

    def test_trailing_colons_are_empty_fields(self):
        p = IgnorePattern.parse("injection.sql_concat::")
        assert p.rule == "injection.sql_concat"
        assert p.file is None
        assert p.line is None

    def test_compile_ignores_batch(self):
        pats = compile_ignores(["a.*", "b:c:3"])
        assert len(pats) == 2
        assert pats[0].rule == "a.*"
        assert pats[1].line == 3


class TestIgnorePatternMatches:
    def test_glob_matches_rule_id(self):
        p = IgnorePattern.parse("crypto.*")
        assert p.matches("crypto.ecb_mode", "app.py", 3)

    def test_glob_matches_basename(self):
        p = IgnorePattern.parse("*.py")
        assert p.matches("secrets.hardcoded_key", "app.py", 3)

    def test_glob_matches_relpath(self):
        p = IgnorePattern.parse("tests/*.py")
        assert p.matches("secrets.hardcoded_key", "tests/sub/app.py", 9)

    def test_glob_does_not_match_other_rule(self):
        p = IgnorePattern.parse("crypto.*")
        assert not p.matches("secrets.hardcoded_key", "app.py", 3)

    def test_rule_file_all_parts_must_match(self):
        p = IgnorePattern.parse("injection.sql_concat:app.py")
        assert p.matches("injection.sql_concat", "app.py", 5)
        assert not p.matches("injection.sql_concat", "other.py", 5)
        assert not p.matches("injection.shell_concat", "app.py", 5)

    def test_line_requires_exact_match(self):
        p = IgnorePattern.parse("crypto.md5_or_sha1:app.py:11")
        assert p.matches("crypto.md5_or_sha1", "app.py", 11)
        assert not p.matches("crypto.md5_or_sha1", "app.py", 12)

    def test_rule_only_matches_any_file(self):
        p = IgnorePattern.parse("deps.unpinned_package")
        assert p.matches("deps.unpinned_package", "requirements.txt", 1)
        assert p.matches("deps.unpinned_package", "package.json", 4)

    def test_windows_drive_path_not_crashing(self):
        p = IgnorePattern.parse("secrets.*")
        assert p.matches("secrets.hardcoded_key", "C:/proj/app.py", 1)


@pytest.fixture
def bad_copy(tmp_path):
    """A writable copy of the intentionally-vulnerable fixture tree."""
    src = os.path.join(os.path.dirname(__file__), "..", "fixtures", "scan_bad")
    dst = tmp_path / "scan_bad"
    shutil.copytree(src, str(dst))
    return str(dst)


class TestIgnoreIntegration:
    """scan_bad yields 507 findings; sql_concat x237, shell_concat x137,
    crypto.* x9, xss medium x3."""

    def test_cli_ignore_reduces_findings(self, bad_copy, capsys):
        rc = main([bad_copy, "--no-save", "--ignore", "injection.sql_concat",
                   "--history-dir", "unused"])
        out = capsys.readouterr().out
        assert rc == 1  # high/critical findings remain, --fail-on high gate holds
        assert "发现 270 个问题" in out  # 507 - 237 suppressed
        assert "已忽略 237 个发现" in out

    def test_glob_ignore_suppresses_rule_family(self, bad_copy, capsys):
        rc = main([bad_copy, "--no-save", "--ignore", "crypto.*",
                   "--history-dir", "unused"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "发现 498 个问题" in out  # 507 - 9 crypto
        assert "已忽略 9 个发现" in out

    def test_rule_file_line_form(self, bad_copy, capsys):
        # Only suppress the sql_concat hit at line 11; the line-19 one stays.
        rc = main([bad_copy, "--no-save", "--format", "json",
                   "--ignore", "injection.sql_concat:injection.py:11",
                   "--history-dir", "unused"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert len(doc["suppressed"]) == 1
        assert doc["suppressed"][0]["line"] == 11
        assert any(
            f["rule_id"] == "injection.sql_concat" and f["line"] == 19
            for f in doc["findings"]
        ), "the line-19 sql_concat finding must remain"

    def test_json_output_contains_suppressed(self, bad_copy, capsys):
        rc = main([bad_copy, "--no-save", "--format", "json",
                   "--ignore", "injection.sql_concat",
                   "--history-dir", "unused"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert len(doc["suppressed"]) == 237
        assert {f["rule_id"] for f in doc["suppressed"]} == {"injection.sql_concat"}
        # Kept findings no longer include the suppressed rules.
        assert not any(f["rule_id"] == "injection.sql_concat" for f in doc["findings"])

    def test_config_file_suppresses(self, bad_copy, capsys):
        with open(os.path.join(bad_copy, ".cursor-scan.json"), "w") as fh:
            json.dump({"ignore": ["crypto.*"]}, fh)
        rc = main([bad_copy, "--no-save", "--history-dir", "unused"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "已忽略 9 个发现" in out
        # The config file itself must not show up as a scanned source file.
        assert "cursor-scan.json" not in out

    def test_cli_and_config_combine(self, bad_copy, capsys):
        with open(os.path.join(bad_copy, ".cursor-scan.json"), "w") as fh:
            json.dump({"ignore": ["crypto.*"]}, fh)
        rc = main([bad_copy, "--no-save", "--ignore", "injection.sql_concat",
                   "--history-dir", "unused"])
        out = capsys.readouterr().out
        assert rc == 1
        assert "已忽略 246 个发现" in out  # 9 crypto + 237 sql_concat

    def test_suppress_all_flips_gate_to_clean(self, bad_copy, capsys):
        with open(os.path.join(bad_copy, ".cursor-scan.json"), "w") as fh:
            json.dump({"ignore": ["*"]}, fh)
        rc = main([bad_copy, "--no-save", "--history-dir", "unused"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "没有发现安全问题" in out

    def test_suppressed_not_scored(self, bad_copy, capsys):
        # Suppressing every high/critical finding must raise the score.
        with open(os.path.join(bad_copy, ".cursor-scan.json"), "w") as fh:
            json.dump({"ignore": ["crypto.*"]}, fh)
        main([bad_copy, "--no-save", "--format", "json", "--history-dir", "unused"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["score"] > 17  # suppressing 9 crypto.* findings raises the score (7 -> 20)

    def test_saved_snapshot_carries_suppressed(self, bad_copy, tmp_path, capsys):
        # Snapshots (history/dashboard input) must round-trip suppressed
        # findings exactly like the CLI JSON output does.
        rc = main([bad_copy, "--ignore", "crypto.*", "--no-save",
                   "--format", "json", "--history-dir", "unused"])
        assert rc == 1
        cli_doc = json.loads(capsys.readouterr().out)

        rc = main([bad_copy, "--ignore", "crypto.*",
                   "--history-dir", str(tmp_path)])
        assert rc == 1
        capsys.readouterr()
        snap_path = sorted(tmp_path.glob("*.json"))[-1]
        with open(snap_path, encoding="utf-8") as fh:
            snap_doc = json.load(fh)

        assert len(snap_doc["suppressed"]) == len(cli_doc["suppressed"]) == 9
        kept_cli = {f["rule_id"] for f in cli_doc["findings"]}
        assert all(f["rule_id"] not in kept_cli for f in snap_doc["suppressed"])
