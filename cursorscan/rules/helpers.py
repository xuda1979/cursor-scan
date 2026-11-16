"""Shared helpers for line-oriented (regex) rules.

Regex rules operate line-by-line on source text.  Running them on raw lines
causes false positives because documentation prose mentions the same
keywords as real vulnerabilities ("DES", "ECB", "SHA1", "pickle", ...).
``code_lines`` reduces each line before rules see it:

* contents of triple-quoted strings (docstrings) are dropped;
* C-style ``/* ... */`` block comments are dropped (multi-line aware);
* inline ``#`` and ``//`` comments are stripped (string-aware);
* ordinary quoted string literals keep their contents so secret-value checks
  (AWS keys, tokens, generic ``KEY = "value"`` assignments) still match;
* regex-pattern definition lines (``re.compile(...)``) are skipped so rules
  do not match their own pattern text.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional, Tuple


def _scan_line(
    raw: str,
    in_triple: bool,
    triple_ch: str,
    in_block: bool,
) -> Tuple[str, bool, str, bool]:
    """Reduce one line. Returns (reduced, in_triple, triple_ch, in_block)."""
    chars: list[str] = []
    n = len(raw)
    i = 0
    while i < n:
        if in_block:
            end = raw.find("*/", i)
            if end == -1:
                return "".join(chars), in_triple, triple_ch, True
            i = end + 2
            in_block = False
            continue
        if in_triple:
            end = raw.find(triple_ch * 3, i)
            if end == -1:
                return "".join(chars), True, triple_ch, False
            i = end + 3
            in_triple = False
            continue

        ch = raw[i]
        # C-style block comment start.
        if raw.startswith("/*", i):
            in_block = True
            i += 2
            continue
        # Triple-quoted string (docstring) start.
        if ch in "\"'" and raw.startswith(ch * 3, i):
            in_triple = True
            triple_ch = ch
            i += 3
            continue
        # Ordinary quoted literal / backtick template: keep full contents.
        if ch in "\"'`":
            chars.append(ch)
            i += 1
            while i < n:
                if raw[i] == "\\" and i + 1 < n:
                    chars.extend((raw[i], raw[i + 1]))
                    i += 2
                    continue
                if raw[i] == ch:
                    chars.append(ch)
                    i += 1
                    break
                chars.append(raw[i])
                i += 1
            continue
        # Inline comments.
        if ch == "#" or raw.startswith("//", i):
            break
        chars.append(ch)
        i += 1
    return "".join(chars), in_triple, triple_ch, in_block


def code_lines(source: str) -> Iterator[Tuple[int, str]]:
    """Yield ``(lineno, reduced_text)`` for every line of ``source``."""
    in_triple = False
    triple_ch = ""
    in_block = False

    for lineno, raw in enumerate(source.splitlines(), start=1):
        reduced, in_triple, triple_ch, in_block = _scan_line(
            raw, in_triple, triple_ch, in_block
        )
        if _is_regex_definition(reduced):
            continue  # regex pattern definitions must not match their own text
        yield lineno, reduced


_REGEX_DEFINITION = re.compile(r"\s*(?:[A-Za-z_]\w*\s*=\s*)?(?:re\.)?(?:compile|fullmatch|match|search|findall|finditer|sub|split)\s*\(")


def _is_regex_definition(reduced: str) -> bool:
    """True when the reduced line defines a compiled regex / regex call."""
    return bool(_REGEX_DEFINITION.match(reduced))
