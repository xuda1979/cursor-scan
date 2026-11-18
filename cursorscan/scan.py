"""Project scanner orchestration: file discovery, rule dispatch, scoring.

Walks a target directory, excludes VCS/dependency/vendored trees, dispatches
each text source file to the language-aware AST scanners (Python / JS / TS)
and applies the regex fallback + secret rules to every text file, then runs
project-level rules (e.g. access control) and produces a ``ScanResult`` with
a per-dimension scorecard.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from .ignore import IgnorePattern, compile_ignores
from .models import Evidence, ScanResult, Scorecard
from .rules import (access_control, crypto, deps, deserialization, injection,
                    permissions, secrets, xss)
from .scanners import ast as ast_scanners

# Directories always skipped, regardless of ignore files.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".bzr",
    "node_modules", "bower_components",
    ".venv", "venv", "env", "virtualenv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", "dist", "build", ".cache", ".tox", ".eggs",
    ".future-code", ".idea", ".vscode",
}

# Extensions never opened for scanning.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".pdf", ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz",
    ".xz", ".bz2", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".lock", ".min.js", ".map",
}

# Known binary sniff: NUL byte in the first 8 KB.
_BINARY_RE = re.compile(rb"[\x00\x01\x02]")

# Extensions treated as source for the *regex* rules even when no AST grammar
# exists for them.
TEXT_EXTS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".rb", ".php", ".go", ".rs", ".java", ".kt", ".sh", ".bash", ".zsh", ".pl",
    ".lua", ".r", ".swift", ".c", ".h", ".cpp", ".hpp", ".cs", ".ps1", ".sql",
    ".vb", ".scala", ".groovy", ".gradle", ".dart", ".m", ".mm", ".ex", ".exs",
    ".erl", ".hrl", ".jl", ".hs", ".lhs", ".clj", ".cljs", ".cljc", ".fs",
    ".fsi", ".fsx", ".pas", ".pp", ".dpr", ".vbs", ".asp", ".cfm", ".cfc",
    ".tcl", ".vue", ".svelte", ".yml", ".yaml", ".json", ".toml", ".ini", ".env", ".properties",
    ".tf", ".cfg", ".conf",
}

# Config / manifest files that often carry hardcoded secrets or odd permissions.
ALWAYS_TEXT = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile",
    "requirements.txt", "package.json", "package-lock.json", "Pipfile",
    "Pipfile.lock", ".env", ".npmrc", ".pypirc", "Gemfile", "Gemfile.lock",
    "composer.json", "go.mod", "go.sum", "Cargo.toml", "setup.py", "pyproject.toml",
    "Procfile", ".gitlab-ci.yml", ".github", ".dockerignore", "README.md",
}


# Base filename of the optional per-project suppression config.
CONFIG_NAME = ".cursor-scan.json"


@dataclass
class ScanOptions:
    """Tunables for a scan run."""

    max_bytes: int = 2 * 1024 * 1024  # skip files larger than 2 MB
    follow_symlinks: bool = False
    ignore_patterns: List[IgnorePattern] = field(default_factory=list)


def _is_binary(data: bytes) -> bool:
    head = data[:8192]
    return bool(_BINARY_RE.search(head)) or b"\x00" in head


def _read_text(path: str, max_bytes: int) -> Tuple[str, Optional[str]]:
    """Return (source_text, encoding_error). skips binary / oversized files."""
    try:
        stat = os.stat(path)
    except OSError:
        return "", "unreadable"
    if stat.st_size > max_bytes:
        return "", "too_large"
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return "", "unreadable"
    if _is_binary(data):
        return "", "binary"
    try:
        return data.decode("utf-8", errors="strict"), None
    except UnicodeDecodeError:
        # Fall back to latin-1 so the file still gets regex scanning.
        return data.decode("latin-1", errors="replace"), "encoding"


def _iter_source_files(root: str, opts: ScanOptions) -> Iterable[str]:
    """Yield relative paths of files worth scanning, in stable order."""
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        )
        for name in sorted(filenames):
            if name == CONFIG_NAME:
                continue  # the tool's own config is never scanned
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            low = name.lower()
            ext = os.path.splitext(low)[1]
            if ext in SKIP_EXTS:
                continue
            if low in ALWAYS_TEXT or ext in TEXT_EXTS:
                yield rel


def _scan_file(root: str, rel: str, src: str, findings: List[Evidence]) -> None:
    if not src:
        return

    lang = ast_scanners.lang_for_file(rel)
    if lang == "python":
        try:
            ast_scanners.analyze_python(path_of(root, rel), src, findings)
        except Exception as exc:  # never let one file crash a scan
            findings.append(_internal_error(path_of(root, rel), exc))
    elif lang in ("javascript", "typescript"):
        try:
            ast_scanners.analyze_jsts(path_of(root, rel), src, findings)
        except Exception as exc:
            findings.append(_internal_error(path_of(root, rel), exc))

    # Regex fallback + secret rules apply to every text file; dependency-
    # manifest rules (requirements*.txt / package.json) are per-file too.
    for runner in (crypto, injection, deserialization, permissions):
        findings.extend(runner.analyze_code(path_of(root, rel), src))
    findings.extend(secrets.analyze_code(path_of(root, rel), src))
    findings.extend(deps.analyze_code(path_of(root, rel), src))
    findings.extend(xss.analyze_code(path_of(root, rel), src))


def path_of(root: str, rel: str) -> str:
    return os.path.join(root, rel)


def _internal_error(path: str, exc: Exception) -> Evidence:
    return Evidence(
        rule_id="internal.scan_error",
        title="扫描器异常",
        severity="low",
        file=path,
        line=0,
        message=f"AST 扫描失败: {exc}",
        fix="检查文件语法",
        dimension="injection",
    )


def _load_config(target: str) -> List[IgnorePattern]:
    """Load ``.cursor-scan.json`` from the target; return ignore patterns.

    A missing or malformed config is ignored (a warning would spam every scan
    on projects that never heard of this file).
    """
    cfg = os.path.join(target, CONFIG_NAME)
    if not os.path.isfile(cfg):
        return []
    try:
        with open(cfg, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    specs = doc.get("ignore", []) if isinstance(doc, dict) else []
    if not isinstance(specs, list):
        return []
    return compile_ignores([s for s in specs if isinstance(s, str)])


def scan_project(target: str, options: Optional[ScanOptions] = None) -> ScanResult:
    """Scan a project directory and return the aggregate result."""
    options = options or ScanOptions()
    target = os.path.abspath(target)
    started = time.monotonic()
    result = ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    if not os.path.isdir(target):
        raise NotADirectoryError(f"扫描目标不存在或不是目录: {target}")

    # CLI --ignore patterns are combined with any in the config file, so both
    # sources are always honoured.
    patterns = list(options.ignore_patterns) + _load_config(target)

    rels = sorted(_iter_source_files(target, options))
    file_texts: Dict[str, List[Tuple[int, str]]] = {}

    for rel in rels:
        path = os.path.join(target, rel)
        src, _ = _read_text(path, options.max_bytes)
        if not src:
            result.skipped_files += 1
            continue
        result.scanned_files += 1
        _scan_file(target, rel, src, result.findings)
        file_texts[rel] = list(enumerate(src.splitlines(), start=1))

    # Project-level rules (needs the whole tree's text).
    access_control.analyze_project(file_texts, result.findings)

    result.duration_sec = round(time.monotonic() - started, 3)
    _finalize(result, patterns, target)
    _backfill_snippets(result, file_texts, target)
    return result


def _backfill_snippets(result: ScanResult,
                       file_texts: Dict[str, List[Tuple[int, str]]],
                       target: str) -> None:
    """Resolve the offending source line for every finding.

    Rules report file/line only; the exact code fragment is filled in here so
    JSON / SARIF output and the web dashboard all carry the same snippet.
    ``access_control`` findings reference files by relative path while per-file
    rules use the absolute path, so both keys are indexed.
    """
    by_path: Dict[str, List[Tuple[int, str]]] = dict(file_texts)
    for rel, lines in file_texts.items():
        by_path[os.path.join(target, rel)] = lines
    for f in list(result.findings) + list(result.suppressed):
        if f.code_snippet or f.line <= 0:
            continue
        lines = by_path.get(f.file)
        if lines is None:
            try:
                lines = by_path.get(os.path.relpath(f.file, target))
            except ValueError:
                lines = None
        if lines and 0 < f.line <= len(lines):
            f.code_snippet = lines[f.line - 1][1].strip()


def _finalize(result: ScanResult, patterns: List[IgnorePattern] = (),
              target: str = "") -> None:
    """Deduplicate findings, split out suppressed ones, then score the rest."""
    seen: set = set()
    unique: List[Evidence] = []
    for f in result.findings:
        # Deduplicate per rule/file/line so AST + regex rules reporting the
        # same issue on one line collapse to a single finding.
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (f.file, f.line, f.rule_id))
    result.findings = unique

    suppressed: List[Evidence] = []
    if patterns:
        target_abs = os.path.abspath(target)
        kept: List[Evidence] = []
        for f in result.findings:
            try:
                rel = os.path.relpath(f.file, target_abs)
            except ValueError:  # f.file on a different drive (Windows)
                rel = f.file
            if any(p.matches(f.rule_id, rel, f.line) for p in patterns):
                suppressed.append(f)
            else:
                kept.append(f)
        result.findings = kept
        result.suppressed = suppressed

    counts: Dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    result.summary = counts

    Scorecard.from_result(result)
