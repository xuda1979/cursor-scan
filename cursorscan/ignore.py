"""Finding-suppression patterns for cursor-scan.

Patterns come from ``--ignore`` (repeatable) or the ``"ignore"`` list in a
``.cursor-scan.json`` file at the scan target. Two forms are supported:

  * a single glob — matched against the rule ID, the file basename, or the
    file's path relative to the scan target. Examples: ``secrets.*`` (all
    secret rules), ``*.py`` (every finding in Python files),
    ``tests/*.py`` (findings under an ``tests/`` subfolder);
  * ``RULE[:FILE[:LINE]]`` — every present part must match, e.g.
    ``deps.known_vulnerable``, ``injection.sql_concat:injection.py`` or
    ``injection.sql_concat:injection.py:11``.

Matching is case-sensitive and anchored (``fnmatchcase``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import List, Optional


@dataclass
class IgnorePattern:
    """One parsed suppression pattern (all fields are optional)."""

    rule: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None

    @staticmethod
    def parse(spec: str) -> "IgnorePattern":
        parts = spec.split(":")
        while len(parts) < 3:
            parts.append(None)
        rule, file_pat, line_str = parts[0], parts[1], parts[2]
        # Empty fields from trailing/empty colon parts behave like omitted ones.
        rule = rule or None
        file_pat = file_pat or None
        line = int(line_str) if line_str and line_str.strip().isdigit() else None
        return IgnorePattern(rule=rule, file=file_pat, line=line)

    @staticmethod
    def _match(pat: Optional[str], *values: str) -> bool:
        return pat is None or any(fnmatchcase(v, pat) for v in values)

    def matches(self, rule_id: str, relpath: str, line: int) -> bool:
        """Return True when a finding matches this pattern.

        ``relpath`` is the finding's file path relative to the scan target.
        """
        base = os.path.basename(relpath)
        if self.file is None and self.line is None:
            # Single-field pattern: matches any of rule / basename / relpath.
            return self._match(self.rule, rule_id, base, relpath)
        if not self._match(self.rule, rule_id):
            return False
        if not self._match(self.file, base, relpath):
            return False
        if self.line is not None and line != self.line:
            return False
        return True


def compile_ignores(specs: List[str]) -> List[IgnorePattern]:
    """Parse a list of pattern strings into matchable ``IgnorePattern``s."""
    return [IgnorePattern.parse(s) for s in specs]


def is_suppressed(pattern: IgnorePattern, rule_id: str,
                  relpath: str, line: int) -> bool:
    return pattern.matches(rule_id, relpath, line)
