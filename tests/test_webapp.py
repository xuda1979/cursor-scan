"""Tests for the AC6 offline web dashboard (cursorscan.webapp).

Exercises the pure ``route`` dispatch seam directly (no sockets): page
rendering, JSON APIs, error statuses, path-traversal rejection and the
stored-XSS guard for malicious ``code_snippet`` content.
"""

from __future__ import annotations

import json
import threading
import urllib.request

from cursorscan.history import save_snapshot
from cursorscan.models import Evidence, ScanResult
from cursorscan.webapp import make_server, route


def _finding(rule_id: str, file: str, line: int, sev: str = "high",
             snippet: str = "") -> Evidence:
    return Evidence(rule_id=rule_id, title="泄漏测试", severity=sev,
                    file=file, line=line, message=f"{rule_id} 命中",
                    fix="修复它", dimension="secrets", code_snippet=snippet)


def _result(score: int = 60, grade: str = "C", target: str = "/tmp/proj",
            findings=None) -> ScanResult:
    r = ScanResult(target=target, score=score, grade=grade,
                   findings=findings or [])
    r.started_at = "2026-11-15T10:00:00Z"
    r.scanned_files = 5
    r.skipped_files = 1
    r.duration_sec = 1.2
    return r


def _seed_history(history_dir: str) -> dict:
    """Write two snapshots (``proj_old`` 60/C, ``proj_new`` 80/B) and return
    the paths so tests can reference the exact JSON filenames.

    Distinct targets give distinct slugs, so ``resolve_snapshot`` can pick
    either latest snapshot by slug prefix ("proj_old" / "proj_new").
    """
    before = _result(score=60, grade="C", target="/tmp/proj_old", findings=[
        _finding("secrets.hardcoded", "app.py", 10),   # fixed in after
        _finding("crypto.weak_hash", "utils.py", 3),   # kept
    ])
    after = _result(score=80, grade="B", target="/tmp/proj_new", findings=[
        _finding("crypto.weak_hash", "utils.py", 3),   # kept
        _finding("injection.sql", "db.py", 7),         # added in after
    ])
    return {
        "before": save_snapshot(before, history_dir),
        "after": save_snapshot(after, history_dir),
    }


class TestIndex:
    def test_index_lists_snapshots(self, tmp_path):
        paths = _seed_history(str(tmp_path))
        status, mime, body = route(str(tmp_path), "/")
        assert status == 200
        assert "text/html" in mime
        html = body.decode("utf-8")
        for p in paths.values():
            name = p.rsplit("/", 1)[-1]
            assert name in html
        assert "60" in html and "80" in html  # both scores listed

    def test_index_empty_history(self, tmp_path):
        status, _, body = route(str(tmp_path), "/")
        assert status == 200
        assert "没有保存的扫描历史" in body.decode("utf-8")


class TestSnapshotPage:
    def test_snapshot_shows_score_grade_and_findings(self, tmp_path):
        _seed_history(str(tmp_path))
        status, _, body = route(str(tmp_path), "/snapshot/proj_new")
        html = body.decode("utf-8")
        assert status == 200
        assert "80" in html and "grade-b" in html
        assert "crypto.weak_hash" in html
        assert "injection.sql" in html

    def test_snapshot_missing_returns_404(self, tmp_path):
        status, _, body = route(str(tmp_path), "/snapshot/nope")
        assert status == 404
        assert "404" in body.decode("utf-8")

    def test_snapshot_shows_suppressed_findings(self, tmp_path):
        r = _result(score=80, grade="B", target="/tmp/proj_new", findings=[
            _finding("injection.sql", "db.py", 7),
        ])
        r.suppressed = [_finding("secrets.hardcoded", "app.py", 10)]
        save_snapshot(r, str(tmp_path))
        status, _, body = route(str(tmp_path), "/snapshot/proj_new")
        html = body.decode("utf-8")
        assert status == 200
        assert "已忽略的发现" in html
        assert "secrets.hardcoded" in html
        # header metric shows the suppressed count
        assert "<span class=\"label\">已忽略</span>" in html
        assert "已忽略的发现（1）" in html

    def test_snapshot_json_api(self, tmp_path):
        paths = _seed_history(str(tmp_path))
        ver, _, body = route(str(tmp_path),
                             "/api/snapshot/" + paths["after"].rsplit("/", 1)[-1])
        assert ver == 200
        doc = json.loads(body.decode("utf-8"))
        assert doc["score"] == 80
        assert doc["grade"] == "B"
        assert len(doc["findings"]) == 2

    def test_snapshot_json_api_optional_suffix(self, tmp_path):
        paths = _seed_history(str(tmp_path))
        fname = paths["after"].rsplit("/", 1)[-1]
        for ref in (fname, fname + ".json", "proj_new", "proj_new.json"):
            ver, mime, body = route(str(tmp_path), "/api/snapshot/" + ref)
            assert ver == 200, f".json suffix on {ref!r} should resolve"
            assert "application/json" in mime
            assert json.loads(body.decode("utf-8"))["grade"] == "B"


class TestDiffPage:
    def test_diff_reports_score_delta_and_partitions(self, tmp_path):
        _seed_history(str(tmp_path))
        status, _, body = route(str(tmp_path), "/diff",
                                {"before": "proj_old", "after": "proj_new"})
        html = body.decode("utf-8")
        assert status == 200
        assert "+20" in html  # 60 -> 80 delta (delta-up class)
        assert "crypto.weak_hash" in html          # kept
        assert "injection.sql" in html             # added
        assert "secrets.hardcoded" in html         # fixed

    def test_diff_unknown_refs_return_404(self, tmp_path):
        status, _, _ = route(str(tmp_path), "/diff",
                             {"before": "nope", "after": "proj_new"})
        assert status == 404

    def test_diff_missing_query_args_return_404(self, tmp_path):
        status, _, _ = route(str(tmp_path), "/diff",
                             {"before": "proj_old"})
        assert status == 404


class TestSecurity:
    def test_path_traversal_rejected(self, tmp_path):
        _seed_history(str(tmp_path))
        for bad in ("../secret.json", "..%2F..%2Fetc%2Fpasswd",
                    "sub/../../x", "/etc/passwd", "x/../y"):
            status, _, _ = route(str(tmp_path), f"/snapshot/{bad}")
            assert status == 404, f"traversal {bad!r} was not rejected"

    def test_snippet_escaped_against_xss(self, tmp_path):
        evil = '<script>alert("x")</script><img src=x onerror=alert(1)>'
        r = _result(findings=[_finding("secrets.hardcoded", "app.py", 1,
                                       snippet=evil)])
        save_snapshot(r, str(tmp_path))
        status, _, body = route(str(tmp_path), "/snapshot/proj")
        html = body.decode("utf-8")
        assert status == 200
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_unknown_route_returns_404(self, tmp_path):
        status, _, body = route(str(tmp_path), "/no-such-page")
        assert status == 404
        assert "404" in body.decode("utf-8")


class TestHistoryApi:
    def test_history_json_shape(self, tmp_path):
        _seed_history(str(tmp_path))
        status, _, body = route(str(tmp_path), "/api/history.json")
        assert status == 200
        doc = json.loads(body.decode("utf-8"))
        assert len(doc["entries"]) == 2
        e = doc["entries"][0]
        for key in ("file", "target", "started_at", "score", "grade",
                    "findings", "scanned_files"):
            assert key in e


class TestHttpHandler:
    def test_end_to_end_over_http(self, tmp_path):
        """Exercise make_server + DashboardHandler over a real socket."""
        _seed_history(str(tmp_path))
        httpd = make_server(str(tmp_path), host="127.0.0.1", port=0)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/history.json",
                    timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers["Content-Type"].startswith("application/json")
                doc = json.loads(resp.read().decode("utf-8"))
                assert len(doc["entries"]) == 2
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=5) as resp:
                assert "扫描历史" in resp.read().decode("utf-8")
        finally:
            httpd.shutdown()
            httpd.server_close()
