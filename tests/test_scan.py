"""End-to-end scanner tests against the scan_bad / scan_good fixture trees.

AC1: >=90% detection on the deliberately-vulnerable fixture.
AC2: zero false positives on the clean fixture.
AC3: the scorecard (0-100 + A-F grade) is produced and explainable.
"""

from __future__ import annotations

import os

import pytest

from cursorscan.models import DIMENSIONS, Evidence, Scorecard
from cursorscan.scan import ScanOptions, scan_project


# The exact vulnerable lines planted in fixtures/scan_bad.  If a check stops
# firing, this table is where the regression shows up.
BAD_EXPECTED = [
    # source file, expected rule_ids present
    ("deserialization.py", {"deser.pickle", "deser.yaml_load", "deser.eval", "deser.exec"}),
    ("injection.py", {"injection.sql_concat", "injection.shell_concat"}),
    ("permissions.py", {"perms.chmod_world_writable", "perms.world_writable_dir",
                        "perms.tmp_write_insecure"}),
    ("access_control_flask.py", {"access_control.missing_auth"}),
    ("access_control_api.js", {"access_control.missing_auth"}),
    ("secrets.py", {"secrets.aws_access_key", "secrets.aws_secret_key",
                    "secrets.slack_token", "secrets.github_token",
                    "secrets.google_api_key", "secrets.private_key", "secrets.stripe_key",
                    "secrets.hardcoded_key"}),
    ("weak_crypto.py", {"crypto.md5_or_sha1", "crypto.weak_cipher_des", "crypto.ecb_mode",
                        "crypto.fixed_iv", "crypto.hardcoded_seed"}),
    ("requirements.txt", {"deps.known_vulnerable"}),
    ("package.json", {"deps.known_vulnerable"}),
    ("xss.py", {"xss.template_render"}),
    ("xss.js", {"xss.dom_manipulation", "xss.dangerous_react", "xss.document_write"}),
]


@pytest.fixture(scope="module")
def bad_result(scan_bad_dir):
    return scan_project(scan_bad_dir)


@pytest.fixture(scope="module")
def good_result(scan_good_dir):
    return scan_project(scan_good_dir)


def _by_file(result):
    per_file: dict[str, set[str]] = {}
    for f in result.findings:
        base = os.path.basename(f.file)
        per_file.setdefault(base, set()).add(f.rule_id)
    return per_file


class TestDetectionRate:
    """AC1: every deliberately planted vulnerability is reported."""

    def test_no_crash_and_scans_every_file(self, bad_result):
        assert bad_result.scanned_files >= 5

    def test_all_expected_rules_fire(self, bad_result):
        per_file = _by_file(bad_result)
        missing = []
        for rel, expected in BAD_EXPECTED:
            got = per_file.get(rel, set())
            for rule in sorted(expected):
                if rule not in got:
                    missing.append(f"{rel}:{rule}")
        assert not missing, f"missed rules: {missing}"

    def test_detection_rate_at_least_pct(self, bad_result):
        per_file = _by_file(bad_result)
        total_expected = sum(len(rules) for _, rules in BAD_EXPECTED)
        total_hit = sum(
            len(expected & per_file.get(rel, set()))
            for rel, expected in BAD_EXPECTED
        )
        assert total_hit / total_expected >= 0.9, "detection rate below 90%"

    def test_findings_have_evidence_fields(self, bad_result):
        for f in bad_result.findings:
            assert f.file and f.line > 0
            assert f.rule_id and f.message and f.fix
            assert f.severity in ("low", "medium", "high", "critical")

    def test_findings_carry_offending_source_line(self, bad_result):
        """Every finding resolves to a real code snippet (the dashboard and
        SARIF ``region.snippet.text`` both rely on this backfill)."""
        src_by_file: dict[str, dict[int, str]] = {}
        for root, _, names in os.walk(bad_result.target):
            for name in names:
                p = os.path.join(root, name)
                try:
                    with open(p, encoding="utf-8") as fh:
                        src_by_file.setdefault(p, {}).update(
                            dict(enumerate(fh.read().splitlines(), start=1)))
                except (OSError, UnicodeDecodeError):
                    continue
        for f in bad_result.findings:
            assert f.code_snippet, f"{f.rule_id}@{f.file}:{f.line} has no snippet"
            src = src_by_file.get(f.file)
            if src is not None and f.line in src:
                assert f.code_snippet == src[f.line].strip(), \
                    f"snippet for {f.rule_id}@{f.file}:{f.line} is not the source line"


class TestZeroFalsePositives:
    """AC2: the clean fixture tree must produce no findings at all."""

    def test_good_tree_is_clean(self, good_result):
        assert good_result.findings == []
        assert good_result.score == 100
        assert good_result.grade == "A"

    def test_all_good_files_scanned(self, good_result):
        assert good_result.scanned_files >= 5
        assert good_result.skipped_files == 0


class TestScorecard:
    """AC3: coherent 0-100 score + grade for both trees."""

    def test_bad_tree_scores_poorly(self, bad_result):
        assert 0 <= bad_result.score < 90
        assert bad_result.grade in ("B", "C", "D", "F")
        assert bad_result.summary["critical"] >= 10

    def test_dimensions_are_scored(self, bad_result):
        assert len(bad_result.dimensions) >= 4
        for name, dim in bad_result.dimensions.items():
            assert 0 <= dim.score <= 100
            assert dim.count == len(dim.findings)

    def test_every_finding_lives_in_a_scored_dimension(self, bad_result):
        scored = {
            (f.rule_id, f.file, f.line)
            for dim in bad_result.dimensions.values() for f in dim.findings
        }
        assert {(f.rule_id, f.file, f.line) for f in bad_result.findings} == scored

    def test_scorecard_from_result_populates_result(self, bad_result):
        card = Scorecard.from_result(bad_result)
        assert card.grade == bad_result.grade
        assert card.overall == bad_result.score


class TestPipelineInternals:
    """Input sanitisation and scan options."""

    def test_skips_binary_and_oversized(self, tmp_path):
        # Realistic skipping: the binary file IS a text-extension .py (so it is
        # yielded for scanning) but carries a NUL byte; big.py exceeds the
        # max_bytes cap. Both end up counted in skipped_files.
        blob = tmp_path / "blob.py"
        blob.write_bytes(b"\x00\x01\x02" + b"a" * 100)
        big = tmp_path / "big.py"
        big.write_text("a" * 3000)
        result = scan_project(str(tmp_path), ScanOptions(max_bytes=1000))
        assert result.scanned_files == 0
        assert result.skipped_files == 2

    def test_not_a_directory_raises(self):
        from cursorscan.scan import scan_project
        with pytest.raises(NotADirectoryError):
            scan_project("/nonexistent/path/that/does/not/exist")
