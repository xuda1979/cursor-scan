"""Unsafe file permissions: chmod 0777 / 0666, writing to /tmp, world-writable mkdir."""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

RE_CHMOD_0777 = re.compile(
    r"\b(?:os\.chmod|chmod)\s*\(\s*[^,]+,\s*(0o?777|0o?666|0x1ff|777|666)\b"
)
RE_MKDIR_WORLD = re.compile(
    r"\b(?:os\.makedirs?|mkdir)\s*\(\s*[^)]*(?:0o?777|mode\s*=\s*0o?777|,?\s*777)\s*\)"
)
RE_TMP_WRITE = re.compile(
    r"\bopen\s*\(\s*[\"']/tmp/[^)\"']*",
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity="high", file=source_path,
                        line=line, message=msg, fix=fix, dimension="permissions")

    for lineno, raw in code_lines(code):
        if RE_CHMOD_0777.search(raw):
            findings.append(hit(lineno, "perms.chmod_world_writable", "世界可写 chmod",
                                "设置文件/目录为 0777 或 0666，任何用户可写", "改为 0o600/0o700"))
        if RE_MKDIR_WORLD.search(raw):
            findings.append(hit(lineno, "perms.world_writable_dir", "世界可写目录",
                                "以 0777 创建目录", "使用 0o700 (私有目录)"))
        if RE_TMP_WRITE.search(raw):
            findings.append(hit(lineno, "perms.tmp_write_insecure", "不安全 /tmp 写入",
                                "直接写 /tmp 易受符号链接攻击 (symlink attack)", "使用 tempfile.mkstemp 私有文件"))
    return findings
