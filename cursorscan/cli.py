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
from typing import Dict, List

from . import __version__
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
    p.add_argument("--version", action="version", version=f"cursor-scan {__version__}")
    return p


def _env_toggle(name: str) -> bool:
    val = os.environ.get(name, "")
    return val.strip().lower() in ("1", "true", "yes", "on")


def main(argv: List[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    options = ScanOptions(max_bytes=args.max_bytes)

    try:
        result = scan_project(args.path, options)
    except NotADirectoryError as exc:
        print(f"cursor-scan: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"cursor-scan: 无权限读取目标: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2))
    elif args.format == "sarif":
        print(json.dumps(result_to_sarif(result), ensure_ascii=False, indent=2))
    else:
        print_text_report(result)

    threshold = SEVERITY_ORDER[args.fail_on]
    gate_findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] >= threshold]
    if gate_findings:
        return 1
    return 0


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
