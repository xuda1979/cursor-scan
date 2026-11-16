"""Command-line interface: scan a project, print the scorecard, emit
text / JSON / SARIF output and enforce an exit-code gate.

Exit codes:
  0  scan completed and no findings at/above the gate threshold
  1  scan completed with findings at/above the gate threshold
  2  usage / environment error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from . import __version__
from .history import (diff_snapshots, list_history, load_snapshot,
                      resolve_snapshot, result_to_dict, save_snapshot)
from .models import Evidence, ScanResult, SEVERITY_ORDER
from .scan import ScanOptions, scan_project

SEVERITY_NAMES = ("low", "medium", "high", "critical")

# Minimal SARIF 2.1.0 doc with one run per scan.
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "cursor-scan"


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cursor-scan",
        description="Local security-debt scanner for vibe-coded projects.",
    )
    p.add_argument("path", nargs="?", default=".", help="project directory to scan")
    p.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text",
        help="output format (default: text)",
    )
    p.add_argument(
        "--fail-on", choices=SEVERITY_NAMES, default="high",
        help="exit 1 when findings at/above this severity exist (default: high)",
    )
    p.add_argument(
        "--max-bytes", type=int, default=2 * 1024 * 1024,
        help="skip source files larger than this many bytes (default: 2 MiB)",
    )
    p.add_argument(
        "--history-dir", default=None,
        help="directory for scan snapshots (default: ./history)",
    )
    p.add_argument(
        "--no-save", action="store_true",
        help="do not write a snapshot to the history directory",
    )
    p.add_argument(
        "--history", action="store_true",
        help="list saved scan snapshots instead of scanning",
    )
    p.add_argument(
        "--diff", nargs=2, metavar=("BEFORE", "AFTER"),
        help="compare two saved snapshots (target slug or file path)",
    )
    p.add_argument("--version", action="version", version=f"cursor-scan {__version__}")
    return p


def _env_toggle(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.strip().lower() in ("1", "true", "yes", "on")


def main(argv: List[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    options = ScanOptions(max_bytes=args.max_bytes)

    if args.history:
        return _cmd_history(args.history_dir)
    if args.diff:
        try:
            before = load_snapshot(resolve_snapshot(args.diff[0], args.history_dir))
            after = load_snapshot(resolve_snapshot(args.diff[1], args.history_dir))
        except FileNotFoundError as exc:
            print(f"cursor-scan: {exc}", file=sys.stderr)
            return 2
        print_diff(diff_snapshots(before, after))
        return 0

    try:
        result = scan_project(args.path, options)
    except NotADirectoryError as exc:
        print(f"cursor-scan: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"cursor-scan: 无权限读取目标: {exc}", file=sys.stderr)
        return 2

    saved = None
    if not args.no_save:
        try:
            saved = save_snapshot(result, args.history_dir)
        except OSError as exc:
            print(f"cursor-scan: 警告: 保存历史快照失败: {exc}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2))
    elif args.format == "sarif":
        print(json.dumps(result_to_sarif(result), ensure_ascii=False, indent=2))
    else:
        print_text_report(result)
        if saved:
            print(f"\n历史: 快照已保存到 {saved}  (--history 查看, --diff 比较)")

    threshold = SEVERITY_ORDER[args.fail_on]
    gate_findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] >= threshold]
    if gate_findings:
        return 1
    return 0


def _cmd_history(history_dir: Optional[str]) -> int:
    entries = list_history(history_dir)
    if not entries:
        print("没有保存的扫描历史。")
        return 1
    print(f"{len(entries)} 条扫描历史 (最新在前):\n")
    for e in entries:
        print(f"  {e.describe()}")
    print("\n比较: cursor-scan --diff <before> <after>")
    return 0


def print_diff(diff) -> None:
    """Render a two-snapshot ScanDiff as added/fixed/kept finding lines."""
    delta = diff.score_delta
    sign = "+" if delta > 0 else ""
    print(f"评分: {diff.before.get('score', '?')} -> {diff.after.get('score', '?')} "
          f"({sign}{delta})  等级: {diff.before.get('grade', '?')} -> "
          f"{diff.after.get('grade', '?')}")
    print(f"新增 {len(diff.added)} 项, 修复 {len(diff.fixed)} 项, "
          f"仍在 {len(diff.kept)} 项\n")
    for label, items in (("新增", diff.added), ("修复", diff.fixed)):
        for f in items:
            sev = f.get("severity", "?")
            print(f"  [{label}] [{sev.upper():<8}] {f.get('rule_id')}  "
                  f"{f.get('file')}:{f.get('line')}  {f.get('message')}")


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------

def result_to_dict(result: ScanResult) -> dict:
    return {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "target": result.target,
        "started_at": result.started_at,
        "duration_sec": result.duration_sec,
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "score": result.score,
        "grade": result.grade,
        "summary": result.summary,
        "dimensions": {
            d: {"score": dim.score, "count": dim.count}
            for d, dim in sorted(result.dimensions.items())
        },
        "findings": [evidence_to_dict(f) for f in result.findings],
    }


def evidence_to_dict(f: Evidence) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "file": f.file,
        "line": f.line,
        "message": f.message,
        "fix": f.fix,
        "dimension": f.dimension,
        "code_snippet": f.code_snippet,
    }


def result_to_sarif(result: ScanResult) -> dict:
    """Convert a ScanResult into a SARIF 2.1.0 log object."""
    rules = _sarif_rules(result.findings)
    results = []
    for f in result.findings:
        if f.line <= 0:
            region = {}
        else:
            region = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": {"critical": "error", "high": "error",
                      "medium": "warning", "low": "note"}[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": region,
                }
            }],
            "properties": {
                "severity": f.severity,
                "dimension": f.dimension,
                "fix": f.fix,
                "title": f.title,
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": __version__, "rules": rules}},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": result.started_at,
                "endTimeUtc": result.started_at,
                "properties": {
                    "score": result.score,
                    "grade": result.grade,
                    "scanned_files": result.scanned_files,
                },
            }],
        }],
    }


def _sarif_rules(findings: List[Evidence]) -> List[dict]:
    seen: Dict[str, dict] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        seen[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "help": {"text": f.fix, "markdown": f.fix},
            "defaultConfiguration": {"level": "error"},
            "properties": {"dimension": f.dimension},
        }
    return list(seen.values())


# --------------------------------------------------------------------------
# Text report
# --------------------------------------------------------------------------

def print_text_report(result: ScanResult) -> None:
    grade_color = {"A": "", "B": "", "C": "", "D": "", "F": ""}
    _ = grade_color  # keep the mapping for future terminal coloring
    print("=" * 60)
    print(f"cursor-scan {__version__}  —  {result.target}")
    print(
        f"评分: {result.score}/100 等级: {result.grade}   "
        f"文件 {result.scanned_files} 跳过 {result.skipped_files}  "
        f"耗时 {result.duration_sec}s"
    )
    print("=" * 60)
    for d in result.dimensions.values():
        print(f"  {d.dimension:<15} {d.score:>3}/100  {d.count} 个发现")
    total = len(result.findings)
    if total == 0:
        print("\n没有发现安全问题。")
        return
    print(f"\n发现 {total} 个问题:")
    for f in result.findings:
        print(f"\n  [{f.severity.upper():<8}] {f.rule_id}  {f.dimension}")
        print(f"      {f.file}:{f.line}")
        print(f"      {f.message}")
        if f.fix:
            print(f"      修复: {f.fix}")


if __name__ == "__main__":
    raise SystemExit(main())
