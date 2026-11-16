"""AC6 Web dashboard: a zero-dependency, fully-offline dashboard over scan
history snapshots.

Serves the history directory over the Python stdlib ``http.server`` (no
network access, no GPU). It reads the same JSON snapshots the CLI writes, so a
browser can list scan history, inspect one snapshot (scorecard + per-item
evidence) and compare two snapshots without ever leaving the machine.

Routes (all GET):
  /                                 index: list snapshots newest-first
  /snapshot/<name>                  detail page for one snapshot
  /diff?before=<ref>&after=<ref>    two-snapshot comparison
  /api/history.json                 snapshot list as JSON
  /api/snapshot/<name>[.json]       raw snapshot as JSON

The ``route`` function is a pure dispatch that returns ``(status, mime, body)``
and is used both by the HTTP handler and directly by the test-suite.
"""

from __future__ import annotations

import functools
import glob
import html
import json
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

from .history import (default_history_dir, diff_snapshots, list_history,
                      load_snapshot, resolve_snapshot)
from .models import DIMENSION_LABELS, SEVERITY_ORDER

CONTENT_HTML = "text/html; charset=utf-8"
CONTENT_JSON = "application/json; charset=utf-8"

_SEV_CLASS = {"critical": "critical", "high": "high",
              "medium": "medium", "low": "low"}


# --------------------------------------------------------------------------
# Pure request dispatch (also the test seam)
# --------------------------------------------------------------------------

def route(history_dir: str, raw_path: str,
          query: Optional[Dict[str, str]] = None) -> Tuple[int, str, bytes]:
    """Handle one GET request. ``query`` maps parameter name -> first value."""
    hd = os.path.realpath(history_dir)
    path = raw_path.rstrip("/") or "/"
    query = query or {}
    if path == "/":
        return _page_index(hd)
    if path == "/api/history.json":
        return _api_history(hd)
    if path.startswith("/api/snapshot/"):
        return _api_snapshot(hd, path[len("/api/snapshot/"):])
    if path.startswith("/snapshot/"):
        return _page_snapshot(hd, path[len("/snapshot/"):])
    if path == "/diff":
        return _page_diff(hd, query)
    return _page_error(hd, 404, "未知路径", f"路径 {raw_path!r} 不存在。")


def _safe_snapshot_path(history_dir: str, name: str) -> Optional[str]:
    """Resolve ``name`` to a snapshot inside ``history_dir`` (safe, or None).

    Accepts an exact snapshot filename or a target slug (newest match, mirroring
    the CLI's ``resolve_snapshot``). Refuses anything that would escape the
    history directory.
    """
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return None
    hd_real = os.path.realpath(history_dir)
    candidate = os.path.realpath(os.path.join(hd_real, name))
    if not (candidate == hd_real
            or candidate.startswith(hd_real.rstrip(os.sep) + os.sep)):
        return None
    if os.path.isfile(candidate):
        return candidate
    try:
        return resolve_snapshot(name, hd_real)
    except FileNotFoundError:
        return None


# --------------------------------------------------------------------------
# JSON APIs
# --------------------------------------------------------------------------

def _json(status: int, doc: dict) -> Tuple[int, str, bytes]:
    payload = json.dumps(doc, ensure_ascii=False, indent=2)
    return status, CONTENT_JSON, payload.encode("utf-8")


def _api_history(history_dir: str) -> Tuple[int, str, bytes]:
    entries = list_history(history_dir)
    doc = {
        "entries": [{
            "file": os.path.basename(e.path),
            "target": e.target,
            "started_at": e.started_at,
            "score": e.score,
            "grade": e.grade,
            "findings": e.findings,
            "scanned_files": e.scanned_files,
        } for e in entries],
    }
    return _json(200, doc)


def _api_snapshot(history_dir: str, name: str) -> Tuple[int, str, bytes]:
    # Accept an optional trailing ".json" (see route docstring). Try the name
    # verbatim first so a slug/target that legitimately ends in ".json" still
    # resolves; only fall back to the suffix-stripped form.
    path = _safe_snapshot_path(history_dir, name)
    if path is None and name.endswith(".json"):
        path = _safe_snapshot_path(history_dir, name[:-len(".json")])
    if path is None:
        return _json(404, {"error": f"未找到快照: {name!r}"})
    return _json(200, load_snapshot(path))


# --------------------------------------------------------------------------
# HTML rendering helpers
# --------------------------------------------------------------------------

def _e(value) -> str:
    """Escape a value for safe embedding in HTML (XSS guard for findings)."""
    return html.escape(str(value if value is not None else ""), quote=True)


def _grade_class(grade: str) -> str:
    return f"grade-{str(grade).lower()}"


def _ordered_findings(findings: list) -> list:
    def key(f):
        sev = f.get("severity", "low")
        return (-SEVERITY_ORDER.get(sev, 1),
                f.get("file", ""), f.get("line", 0))
    return sorted(findings, key=key)


_PAGE_CSS = """\
:root { color-scheme: light; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0; color: #1f2937; background: #f3f4f6; }
.wrap { max-width: 1000px; margin: 0 auto; padding: 24px 16px 60px; }
header h1 { font-size: 20px; margin: 0 0 4px; }
.sub { color: #6b7280; font-size: 13px; }
table { border-collapse: collapse; width: 100%; background: #fff;
        box-shadow: 0 1px 2px rgba(0,0,0,.06); }
th, td { text-align: left; padding: 8px 10px; font-size: 13px;
         border-bottom: 1px solid #e5e7eb; vertical-align: top; }
th { background: #f9fafb; font-weight: 600; white-space: nowrap; }
a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }
.card { background: #fff; border-radius: 8px; padding: 16px 20px;
        margin-top: 16px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
.card h2 { margin: 0 0 10px; font-size: 15px; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px;
         font-size: 11px; font-weight: 700; color: #fff; white-space: nowrap; }
tr.sev-critical { background: #fef2f2; } tr.sev-critical .badge { background: #b91c1c; }
tr.sev-high { background: #fffbeb; }     tr.sev-high .badge { background: #d97706; }
tr.sev-medium { background: #eff6ff; }   tr.sev-medium .badge { background: #2563eb; }
tr.sev-low .badge { background: #6b7280; }
.score { font-size: 40px; font-weight: 800; line-height: 1; }
.grade-a { color: #15803d; } .grade-b { color: #16a34a; }
.grade-c { color: #ca8a04; } .grade-d { color: #b45309; }
.grade-f { color: #b91c1c; }
pre.snippet { background: #0f172a; color: #e2e8f0; padding: 10px;
              border-radius: 6px; font-size: 12px; overflow-x: auto; }
form.diff { display: flex; gap: 8px; align-items: center; margin: 0;
            flex-wrap: wrap; }
form.diff select { padding: 6px; border: 1px solid #d1d5db; border-radius: 6px;
                   background: #fff; }
button { padding: 6px 14px; border: 0; border-radius: 6px;
         background: #2563eb; color: #fff; cursor: pointer; }
.dim { display: inline-block; margin: 4px 8px 4px 0; padding: 8px 14px;
       border-radius: 8px; background: #f9fafb; border: 1px solid #e5e7eb; }
.dim b { display: block; font-size: 20px; }
.muted { color: #6b7280; }
.metric { display: inline-block; margin-right: 28px; }
.metric .label { font-size: 12px; color: #6b7280; }
.metric .value { font-size: 18px; font-weight: 700; }
.delta-up { color: #15803d; font-weight: 700; }
.delta-down { color: #b91c1c; font-weight: 700; }
"""


def _page(title: str, body: str, nav: str = "",
          status: int = 200) -> Tuple[int, str, bytes]:
    title_html = _e(title) if status == 200 else f"{status} {_e(title)}"
    doc = (
        "<!doctype html>\n<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{title_html} - cursor-scan</title>"
        f"<style>{_PAGE_CSS}</style></head><body>"
        f"<div class=\"wrap\"><header><h1>{title_html}</h1>"
        f"<p class=\"sub\">cursor-scan 离线仪表板</p></header>{nav}{body}"
        "</div></body></html>"
    )
    return status, CONTENT_HTML, doc.encode("utf-8")


def _page_error(history_dir: str, status: int, title: str,
                msg: str) -> Tuple[int, str, bytes]:
    nav = '<p><a href="/">← 历史列表</a></p>'
    body = f'<div class="card"><p>{_e(msg)}</p></div>'
    return _page(title, body, nav, status=status)


def _findings_table(findings: list) -> str:
    if not findings:
        return '<p class="muted">没有发现问题。</p>'
    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        snippet = f.get("code_snippet")
        snip = f'<pre class="snippet">{_e(snippet)}</pre>' if snippet else ""
        rows.append(
            "<tr class=\"{cls}\">"
            "<td><span class=\"badge\">{sev}</span></td>"
            "<td>{rule}</td><td>{dim}</td>"
            "<td>{file}:{line}</td><td>{msg} {snip}</td><td>{fix}</td></tr>"
            .format(
                cls=_SEV_CLASS.get(sev, "low"), sev=sev.upper(),
                rule=_e(f.get("rule_id", "")),
                dim=_e(DIMENSION_LABELS.get(f.get("dimension", ""),
                                            f.get("dimension", ""))),
                file=_e(f.get("file", "")), line=f.get("line", "?"),
                msg=_e(f.get("message", "")), snip=snip,
                fix=_e(f.get("fix", "")),
            )
        )
    return (
        "<table><tr><th>严重度</th><th>规则</th><th>维度</th><th>位置</th>"
        "<th>说明</th><th>修复建议</th></tr>" + "".join(rows) + "</table>"
    )


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def _page_index(history_dir: str) -> Tuple[int, str, bytes]:
    entries = list_history(history_dir)
    nav = ""
    if not entries:
        body = ("<div class=\"card\"><p>没有保存的扫描历史。</p>"
                "<p>先运行 <code>cursor-scan &lt;项目目录&gt;</code> 生成第一张快照，"
                "再回到这里查看。</p></div>")
        return _page("扫描历史", body, nav)

    rows = []
    for e in entries:
        name = os.path.basename(e.path)
        rows.append(
            "<tr><td>{started}</td><td>{target}</td>"
            "<td class=\"{grade_cls}\">{score} / 100</td><td>{grade}</td>"
            "<td>{findings}</td><td>{files}</td>"
            "<td><a href=\"/snapshot/{name}\">查看</a></td></tr>"
            .format(started=_e(e.started_at), target=_e(e.target),
                    grade_cls=_grade_class(e.grade), score=_e(e.score),
                    grade=_e(e.grade), findings=e.findings,
                    files=e.scanned_files,
                    name=urllib.parse.quote(name))
        )
    table = ("<table><tr><th>时间</th><th>目标</th><th>评分</th><th>等级</th>"
             "<th>发现</th><th>文件</th><th></th></tr>"
             + "".join(rows) + "</table>")

    def options(selected_idx: int) -> str:
        out = []
        for i, e in enumerate(entries):
            sel = " selected" if i == selected_idx else ""
            label = (f"{e.started_at}  {e.target}  "
                     f"({e.score}/100 {e.grade})")
            out.append(f'<option value="{urllib.parse.quote(os.path.basename(e.path))}"{sel}>'
                       f"{_e(label)}</option>")
        return "".join(out)

    before_idx = 1 if len(entries) >= 2 else 0
    after_idx = 0
    form = (
        '<form class="diff" method="get" action="/diff">'
        f'<select name="before">{options(before_idx)}</select>'
        f'<select name="after">{options(after_idx)}</select>'
        '<button type="submit">比较两次扫描</button></form>'
    )
    body = (
        '<div class="card"><p class="sub">比较最佳基线（默认取最新两次扫描）。'
        '也可用 CLI：<code>cursor-scan --diff &lt;before&gt; &lt;after&gt;</code></p>'
        + form + "</div>"
        + '<div class="card">' + table + "</div>"
    )
    return _page("扫描历史", body, nav)


def _page_snapshot(history_dir: str, name: str) -> Tuple[int, str, bytes]:
    path = _safe_snapshot_path(history_dir, name)
    if path is None:
        return _page_error(history_dir, 404, "快照不存在",
                           f"未找到快照: {name!r}")
    doc = load_snapshot(path)
    nav = '<p><a href="/">← 历史列表</a></p>'
    header = _score_header(doc)
    dims = "".join(
        '<span class="dim"><b class="{cls}">{score}</b>{label}</span>'
        .format(score=_e(dim.get("score", 0)),
                cls=_grade_class(doc.get("grade", "?")),
                label=_e(DIMENSION_LABELS.get(d, d)))
        for d, dim in sorted(doc.get("dimensions", {}).items())
    ) or '<p class="muted">无维度评分</p>'
    table = _findings_table(doc.get("findings", []))
    body = (header + '<div class="card"><h2>维度评分</h2>' + dims + "</div>"
            + '<div class="card"><h2>逐项证据</h2>' + table + "</div>")
    return _page(f"快照 {os.path.basename(path)}", body, nav)


def _score_header(doc: dict) -> str:
    return (
        '<div class="card"><span class="score">{score}</span>'
        '<span class="{grade_cls}" style="font-size:20px;font-weight:700">'
        ' {grade}</span>'
        '<div style="margin-top:12px">'
        '<span class="metric"><span class="label">目标</span>'
        '<span class="value">{target}</span></span>'
        '<span class="metric"><span class="label">时间</span>'
        '<span class="value">{started}</span></span>'
        '<span class="metric"><span class="label">文件</span>'
        '<span class="value">{scanned} 扫描 / {skipped} 跳过</span></span>'
        '<span class="metric"><span class="label">发现</span>'
        '<span class="value">{findings}</span></span>'
        '<span class="metric"><span class="label">耗时</span>'
        '<span class="value">{dur}s</span></span>'
        "</div></div>"
    ).format(
        score=_e(doc.get("score", 0)),
        grade_cls=_grade_class(doc.get("grade", "?")),
        grade=_e(doc.get("grade", "?")),
        target=_e(doc.get("target", "?")),
        started=_e(doc.get("started_at", "?")),
        scanned=doc.get("scanned_files", 0),
        skipped=doc.get("skipped_files", 0),
        findings=len(doc.get("findings", [])),
        dur=doc.get("duration_sec", "?"),
    )


def _page_diff(history_dir: str, query: Dict[str, str]) -> Tuple[int, str, bytes]:
    nav = '<p><a href="/">← 历史列表</a></p>'
    before_ref, after_ref = query.get("before", ""), query.get("after", "")
    before_path = _safe_snapshot_path(history_dir, before_ref)
    after_path = _safe_snapshot_path(history_dir, after_ref)
    if before_path is None or after_path is None:
        return _page_error(history_dir, 404, "快照不存在",
                           "至少一个快照引用未找到；请从历史列表中选择。")
    before, after = load_snapshot(before_path), load_snapshot(after_path)
    diff = diff_snapshots(before, after)

    delta = diff.score_delta
    delta_html = (f'<span class="delta-up">+{delta}</span>' if delta > 0
                  else f'<span class="delta-down">{delta}</span>' if delta < 0
                  else '<span class="muted">0</span>')
    score_row = (
        f'<div class="card"><h2>评分变化</h2>'
        f'<p class="muted">{_e(os.path.basename(before_path))}  →  '
        f'{_e(os.path.basename(after_path))}</p>'
        f'<span class="score">{before.get("score", "?")}</span>'
        f'<span style="font-size:24px;padding:0 12px">→</span>'
        f'<span class="score">{after.get("score", "?")}</span>'
        f'<span style="padding-left:12px">({delta_html})</span>'
        f'<p>等级 {_e(before.get("grade", "?"))} → '
        f'{_e(after.get("grade", "?"))}；新增 {len(diff.added)} 项、'
        f'修复 {len(diff.fixed)} 项、仍在 {len(diff.kept)} 项。</p></div>'
    )

    def section(title: str, findings: list) -> str:
        details = (
            f'<details class="card" open><summary style="cursor:pointer">'
            f'<h2 style="display:inline;margin:0">{title}'
            f'（{len(findings)}）</h2></summary>'
            + _findings_table(findings) + "</details>"
        ) if findings else ""
        return details

    body = score_row + section("新增", diff.added) + section("修复", diff.fixed)
    kept = ("<details class=\"card\"><summary style=\"cursor:pointer\">"
            f"仍在的问题（{len(diff.kept)}）</summary>"
            + _findings_table(diff.kept) + "</details>"
            if diff.kept else "")
    body += kept
    return _page("扫描差异", body, nav)


# --------------------------------------------------------------------------
# HTTP server wrappers (thin: routing lives in ``route``)
# --------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard. ``history_dir`` is injected by ``make_server``."""

    history_dir: str = "."

    def __init__(self, *args, history_dir: Optional[str] = None, **kwargs):
        if history_dir is not None:
            self.history_dir = history_dir
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        status, mime, body = route(self.history_dir, parsed.path, query)
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *args):  # keep the dashboard console quiet
        pass


def make_server(history_dir: str, host: str = "127.0.0.1", port: int = 0):
    """Build a threaded HTTP server for the dashboard (tests pass port=0)."""
    hd = os.path.realpath(history_dir)
    handler = functools.partial(DashboardHandler, history_dir=hd)
    return ThreadingHTTPServer((host, port), handler)


def run_dashboard(history_dir: Optional[str] = None, host: str = "127.0.0.1",
                  port: int = 8080) -> int:
    """Run the dashboard until Ctrl+C. Returns the process exit code."""
    hd = history_dir or default_history_dir()
    os.makedirs(hd, exist_ok=True)
    httpd = make_server(hd, host, port)
    print(f"cursor-scan dashboard: http://{host}:{httpd.server_address[1]}/")
    print(f"history: {os.path.realpath(hd)}   (Ctrl+C 退出)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
