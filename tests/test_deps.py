"""Tests for the P3 dependency-risk rule (requirements*.txt / package.json).

Covers version comparison helpers, the curated-vuln lookup, and the public
``analyze_code`` entry point against realistic manifest content, plus an
end-to-end assertion that dependency findings flow into the scan pipeline.
"""

from __future__ import annotations

from cursorscan.rules import deps
from cursorscan.rules.deps import (_cmp, _exact_npm_version, _is_floating,
                                  _known_vuln, _ver_tuple)


class TestVersionHelpers:
    def test_ver_tuple_leading_numeric(self):
        assert _ver_tuple("2.10.1") == (2, 10, 1)
        assert _ver_tuple("v1.2-beta") == (1, 2)
        assert _ver_tuple("1.2.3rc1") == (1, 2, 3)

    def test_ver_tuple_unparseable(self):
        assert _ver_tuple("latest") is None
        assert _ver_tuple("foo") is None

    def test_cmp_pads_to_equal_width(self):
        assert _cmp("1.2", "1.2.0") == 0
        assert _cmp("2.10", "2.9.9") == 1
        assert _cmp("1.0.0", "1.0.1") == -1

    def test_cmp_no_parse_none(self):
        assert _cmp("1.0", "latest") is None


class TestKnownVuln:
    def test_at_or_below_last_vulnerable_hits(self):
        cve, sev, note = _known_vuln("jinja2", "2.10.1")
        assert cve == "CVE-2019-8341"
        assert sev == "critical"
        assert note

    def test_above_last_vulnerable_is_clean(self):
        assert _known_vuln("log4j", "2.17.1") is None
        assert _known_vuln("requests", "2.20.0") is None

    def test_unknown_package_is_clean(self):
        assert _known_vuln("not-a-real-pkg", "0.1.0") is None

    def test_case_insensitive(self):
        assert _known_vuln("Flask", "0.12.2") is not None


class TestNpmSpecs:
    def test_exact_pins(self):
        assert _exact_npm_version("4.17.20") == "4.17.20"
        assert _exact_npm_version("=0.21.1") == "0.21.1"
        assert _exact_npm_version("v1.2.3") == "1.2.3"

    def test_ranges_never_exact(self):
        for spec in ("^4.17.0", "~1.2.3", ">=1.0.0", "1.2.x", "*", "latest"):
            assert _exact_npm_version(spec) is None, spec

    def test_is_floating(self):
        for spec in ("*", "latest", "next", "x", "1.x", ">=1.0.0"):
            assert _is_floating(spec), spec
        assert not _is_floating("4.17.20")


class TestAnalyzeRequirements:
    def test_vulnerable_pin_reported(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("jinja2==2.10.1\npyyaml==5.1\n", encoding="utf-8")
        found = deps.analyze_code(str(p), p.read_text(encoding="utf-8"))
        ids = [(f.rule_id, f.line) for f in found]
        assert ("deps.known_vulnerable", 1) in ids
        assert ("deps.known_vulnerable", 2) in ids
        for f in found:
            assert f.dimension == "dependencies"
            assert f.file == str(p)

    def test_fixed_pin_not_reported(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("jinja2==3.1.2\n", encoding="utf-8")
        assert deps.analyze_code(str(p), p.read_text(encoding="utf-8")) == []

    def test_unpinned_gets_low_repro_warning(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("flask\nrequests>=2.10\n", encoding="utf-8")
        found = deps.analyze_code(str(p), p.read_text(encoding="utf-8"))
        assert all(f.rule_id == "deps.unpinned_package" for f in found)
        assert all(f.severity == "low" for f in found)

    def test_comments_and_flags_skipped(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("# comment\n--index-url https://pypi.org/simple\n\njinja2==3.1.2\n",
                     encoding="utf-8")
        assert deps.analyze_code(str(p), p.read_text(encoding="utf-8")) == []

    def test_other_filenames_ignored(self, tmp_path):
        p = tmp_path / "not-reqs.txt"
        p.write_text("jinja==2.10.1\n", encoding="utf-8")
        assert deps.analyze_code(str(p), p.read_text(encoding="utf-8")) == []


class TestAnalyzePackageJson:
    def test_exact_vulnerable_pins_reported(self, tmp_path):
        p = tmp_path / "package.json"
        doc = '{"dependencies": {"lodash": "4.17.20", "axios": "0.21.1"}}'
        p.write_text(doc, encoding="utf-8")
        found = deps.analyze_code(str(p), doc)
        assert [f.rule_id for f in found] == ["deps.known_vulnerable"] * 2

    def test_dev_dependencies_checked(self, tmp_path):
        p = tmp_path / "package.json"
        doc = '{"devDependencies": {"moment": "2.29.3"}}'
        p.write_text(doc, encoding="utf-8")
        found = deps.analyze_code(str(p), doc)
        assert len(found) == 1
        assert found[0].line == 1

    def test_ranges_not_flagged_as_vuln(self, tmp_path):
        p = tmp_path / "package.json"
        doc = '{"dependencies": {"lodash": "^4.17.20", "axios": "~0.21.1"}}'
        p.write_text(doc, encoding="utf-8")
        assert deps.analyze_code(str(p), doc) == []

    def test_floating_reported_as_unpinned(self, tmp_path):
        p = tmp_path / "package.json"
        doc = '{"dependencies": {"minimist": "*"}}'
        p.write_text(doc, encoding="utf-8")
        found = deps.analyze_code(str(p), doc)
        assert found[0].rule_id == "deps.unpinned_package"

    def test_malformed_json_skipped(self, tmp_path):
        p = tmp_path / "package.json"
        p.write_text("{ not json", encoding="utf-8")
        assert deps.analyze_code(str(p), "{ not json") == []


class TestPipelineIntegration:
    def test_deps_findings_in_scan_result(self, scan_bad_dir):
        from cursorscan.scan import scan_project
        result = scan_project(scan_bad_dir)
        dep_findings = [f for f in result.findings
                        if f.dimension == "dependencies"]
        assert dep_findings
        assert "dependencies" in result.dimensions
        assert any(f.rule_id == "deps.known_vulnerable"
                   for f in dep_findings)
