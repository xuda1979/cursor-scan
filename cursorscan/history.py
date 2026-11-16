"""Scan history persistence and two-scan diffing.

Every CLI scan is stored as a JSON snapshot under a history directory
(default: ``./history`` or ``--history-dir``). Snapshots are named
``<target-slug>-<utc-timestamp>.json`` and are plain ScanResult dicts
(see :func:`result_to_dict`) so offline dashboards can read them later.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from . import __version__
from .models import Evidence, ScanResult

HISTORY_DIR_NAME = "history"
_TIMESTAMP_FMT = "%Y%m%d-%H%M%S"


def default_history_dir() -> str:
    return os.path.join(os.getcwd(), HISTORY_DIR_NAME)


# --------------------------------------------------------------------------
# Serialization: single source of truth for the on-disk snapshot shape.
# --------------------------------------------------------------------------

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


def result_to_dict(result: ScanResult) -> dict:
    return {
        "tool": {"name": "cursor-scan", "version": __version__},
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
        "suppressed": [evidence_to_dict(f) for f in result.suppressed],
    }


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def slug_for_target(target: str) -> str:
    base = os.path.basename(os.path.normpath(target)) or "root"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-").lower()
    return slug or "project"


def snapshot_path(target: str, history_dir: str,
                  now: Optional[datetime] = None) -> str:
    slug = slug_for_target(target)
    ts = (now or datetime.now(timezone.utc)).strftime(_TIMESTAMP_FMT)
    base = os.path.join(history_dir, f"{slug}-{ts}")
    path = base + ".json"
    i = 2
    while os.path.exists(path):  # two scans in the same second
        path = f"{base}-{i}.json"
        i += 1
    return path


def save_snapshot(result: ScanResult, history_dir: Optional[str] = None) -> str:
    """Persist a ScanResult as JSON and return the written path.

    Creates the history directory if needed and never raises on a clean
    run; callers that care about durability should check ``os.path.exists``.
    """
    hd = history_dir or default_history_dir()
    os.makedirs(hd, exist_ok=True)
    path = snapshot_path(result.target, hd)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result_to_dict(result), fh, ensure_ascii=False, indent=2)
    return path


@dataclass
class HistoryEntry:
    path: str
    target: str
    started_at: str
    score: int
    grade: str
    findings: int
    scanned_files: int

    def describe(self) -> str:
        return (
            f"{os.path.basename(self.path)}  {self.target}  "
            f"{self.score}/100 {self.grade}  {self.findings} 发现"
        )


def list_history(history_dir: Optional[str] = None) -> List[HistoryEntry]:
    """Return snapshots newest-first; malformed files are skipped."""
    hd = history_dir or default_history_dir()
    if not os.path.isdir(hd):
        return []
    entries = []
    for path in glob.glob(os.path.join(hd, "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        entries.append(HistoryEntry(
            path=path,
            target=doc.get("target", "?"),
            started_at=doc.get("started_at", "?"),
            score=doc.get("score", 0),
            grade=doc.get("grade", "?"),
            findings=len(doc.get("findings", [])),
            scanned_files=doc.get("scanned_files", 0),
        ))
    # File mtime is the save time and is monotonic across writes, so the most
    # recent snapshot reliably sorts first even within the same second.
    entries.sort(key=lambda e: (os.path.getmtime(e.path), e.started_at, e.path),
                 reverse=True)
    return entries


def resolve_snapshot(ref: str, history_dir: Optional[str] = None) -> str:
    """Turn a user reference into a snapshot path.

    ``ref`` is used verbatim when it names an existing file, otherwise it is
    treated as a target slug (or basename prefix) and resolved to the newest
    matching snapshot. Raises FileNotFoundError when nothing matches.
    """
    if os.path.isfile(ref):
        return ref
    hd = history_dir or default_history_dir()
    if not os.path.isdir(hd):
        raise FileNotFoundError(f"历史目录不存在: {hd}")
    slug = slug_for_target(ref)
    matches = [e.path for e in list_history(hd)
               if os.path.basename(e.path).startswith((slug, ref))]
    if not matches:
        raise FileNotFoundError(f"未找到快照: {ref} (历史目录: {hd})")
    return matches[0]  # list_history is newest-first


def load_snapshot(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------

@dataclass
class ScanDiff:
    before: dict
    after: dict
    added: List[dict]     # in after but not before
    fixed: List[dict]     # in before but not after
    kept: List[dict]      # present in both

    @property
    def score_delta(self) -> int:
        return int(self.after.get("score", 0)) - int(self.before.get("score", 0))


def _finding_key(f: dict) -> Tuple[str, str, int]:
    return (f.get("rule_id", "?"), os.path.normpath(f.get("file", "?")),
            f.get("line", 0))


def diff_snapshots(before: dict, after: dict) -> ScanDiff:
    """Compare two scan snapshots by (rule_id, file, line)."""
    before_keyed = {_finding_key(f): f for f in before.get("findings", [])}
    after_keyed = {_finding_key(f): f for f in after.get("findings", [])}
    added = [f for k, f in sorted(after_keyed.items()) if k not in before_keyed]
    fixed = [f for k, f in sorted(before_keyed.items()) if k not in after_keyed]
    kept = [f for k, f in sorted(after_keyed.items()) if k in before_keyed]
    return ScanDiff(before=before, after=after, added=added, fixed=fixed, kept=kept)
