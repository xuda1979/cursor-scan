"""Unsafe deserialization: pickle, unsafe yaml.load, eval/exec on non-literal input.

AST hooks + regex fallback.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

RE_PICKLE = re.compile(
    r"\b(pickle\.(loads?|load)|cPickle\.(loads?|load)|import marshal|marshal\.(loads?))\b"
)
RE_YAML_UNSAFE = re.compile(
    r"\byaml\.unsafe_load\b"
)
RE_YAML_LOAD = re.compile(
    r"\b(yaml\.load|yaml\.load_all)\s*\(.*"
)
RE_EVAL = re.compile(r"\beval\s*\(\s*[^)\"']")
RE_EXEC = re.compile(r"\bexec\s*\(\s*[^)\"']")


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity="critical", file=source_path,
                        line=line, message=msg, fix=fix, dimension="deserialization")

    for lineno, raw in code_lines(code):
        if "import " in raw or "from " in raw:
            if "pickle" not in raw and "marshal" not in raw and "yaml" not in raw:
                continue
            else:
                if "marshal" in raw:
                    # import marshal is itself a use-risk; only flag explicit load.
                    continue
        if RE_PICKLE.search(raw):
            if "load" in raw or "loads" in raw:
                findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (pickle)",
                                    "pickle 反序列化可执行任意代码", "改用 JSON/安全格式"))
        if RE_YAML_UNSAFE.search(raw):
            findings.append(hit(lineno, "deser.yaml_load", "不安全 yaml.load",
                                "yaml.unsafe_load 可执行任意代码", "yaml.safe_load(data)"))
        elif RE_YAML_LOAD.search(raw) and "SafeLoader" not in raw and "UnsafeLoader" not in raw:
            findings.append(hit(lineno, "deser.yaml_load", "不安全 yaml.load",
                                "yaml.load 需要显式安全 Loader (SafeLoader)", "yaml.safe_load(data)"))
        if RE_EVAL.search(raw):
            findings.append(hit(lineno, "deser.eval", "eval 外部输入",
                                "eval 处理外部输入可执行任意代码", "重构解析逻辑，不使用 eval"))
        if RE_EXEC.search(raw):
            findings.append(hit(lineno, "deser.exec", "exec 外部输入",
                                "exec 处理外部输入可执行任意代码", "重构解析逻辑，不使用 exec"))
    return findings
