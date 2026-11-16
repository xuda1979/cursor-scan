"""Unsafe deserialization: pickle, unsafe yaml.load, eval/exec on non-literal input.

AST hooks + regex fallback.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

RE_PICKLE = re.compile(
    r"\b(pickle\.(loads?|load)|cPickle\.(loads?|load)|jsonpickle\.(loads?|load)"
    r"|(?:cloudpickle|dill)\.(loads?|load)|_pickle\.(loads?|load)|joblib\.load"
    r"|(?:pandas|pd)\.read_pickle|import marshal|marshal\.(loads?))\b"
)
# shelve.open(path) opens a pickle-backed database store: records written
# by shelve round-trip through pickle, so reading an untrusted store
# executes arbitrary code during unpickling (CWE-502) -- the store
# counterpart of pickle.load.
RE_SHELVE_OPEN = re.compile(r"\bshelve\.open\s*\(")
# pickle.Unpickler(fp) is the class-based twin of pickle.load: constructing
# it from a file handle (typically followed by .load()) unpickles the data
# stream with the same arbitrary-code-execution surface.
RE_UNPICKLER = re.compile(r"\b(?:_?pickle)\.Unpickler\s*\(")
# Python stdlib XML parsers resolve external entities by default (CWE-611
# XXE): xml.etree / xml.dom / xml.sax / xml.parsers.expat all let a document's
# DOCTYPE read local files and probe internal hosts during parsing. defusedxml
# is the safe replacement; lxml does not resolve external entities by default
# and stays quiet. Both the fully-qualified spellings (xml.etree.ElementTree.
# parse) and the bare module names (minidom / pulldom / ElementTree after a
# from-import) are covered.
RE_XML_PARSE = re.compile(
    r"\b(?:xml\.etree\.(?:c?ElementTree)\.(?:parse|fromstring)"
    r"|xml\.dom\.minidom\.(?:parse|parseString)"
    r"|xml\.dom\.pulldom\.(?:parse|parseString)"
    r"|xml\.sax\.(?:parse|parseString|make_parser)"
    r"|xml\.parsers\.expat\.ParserCreate"
    r"|ElementTree\.(?:parse|fromstring)"
    r"|minidom\.(?:parse|parseString)"
    r"|pulldom\.(?:parse|parseString)"
    r"|expat\.ParserCreate)\s*\(",
)
RE_YAML_UNSAFE = re.compile(
    r"\byaml\.unsafe_load\b"
)
RE_YAML_LOAD = re.compile(
    r"\b(yaml\.load|yaml\.load_all)\s*\(.*"
)
RE_EVAL = re.compile(r"\beval\s*\(\s*[^)\"']")
RE_EXEC = re.compile(r"\bexec\s*\(\s*[^)\"']")
# Node's vm module: runInThisContext / runInNewContext / runInContext execute
# source strings -- the JS counterparts of eval. Like RE_EVAL, a static
# literal operand stays quiet; dynamic source is the dangerous form. Both the
# ``vm.run*`` spelling and the ``require("vm").run*`` form are covered.
RE_VM_RUN = re.compile(
    r"""(?:require\s*\(\s*["'](?:node:)?vm["']\s*\)|\bvm)"""
    r"""\.(?:runInThisContext|runInNewContext|runInContext)\s*\(\s*[^)"']""",
)
# node-serialize's unserialize() deserializes a serialized function graph by
# eval'ing the payload (CVE-2017-5941): any non-literal payload is arbitrary
# code execution, the JS counterpart of Python pickle. Both the bare
# ``unserialize(payload)`` (destructured import) and the ``serialize.
# unserialize(payload)`` dotted spelling are covered; the serialize() writer
# direction and a bare static literal stay quiet.
RE_NODE_UNSERIALIZE = re.compile(
    r"\b(?:serialize\.)?unserialize\s*\(\s*[^)\"']",
)


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
        m = RE_PICKLE.search(raw)
        if m:
            if "load" in m.group(1) or "read_pickle" in m.group(1):
                findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (pickle)",
                                    "pickle 反序列化可执行任意代码", "改用 JSON/安全格式"))
        if RE_SHELVE_OPEN.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (pickle)",
                                "shelve.open 打开 pickle 后端存储，读取不可信数据可执行任意代码",
                                "改用 SQLite/JSON 等安全存储"))
        if RE_UNPICKLER.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (pickle)",
                                "pickle.Unpickler 反序列化可执行任意代码",
                                "改用 JSON/安全格式"))
        if RE_XML_PARSE.search(raw):
            findings.append(hit(lineno, "deser.xxe", "XXE 外部实体注入",
                                "stdlib XML 解析默认解析外部实体，可读取本地文件/内网探测",
                                "改用 defusedxml 或禁用 DTD/外部实体"))
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
        if RE_VM_RUN.search(raw):
            findings.append(hit(lineno, "deser.eval", "vm.run* 外部输入",
                                "vm.runIn*Context 执行外部源代码，可执行任意代码",
                                "重构解析逻辑，不使用 vm 执行用户代码"))
        if RE_NODE_UNSERIALIZE.search(raw):
            findings.append(hit(lineno, "deser.pickle", "node-serialize 反序列化",
                                "unserialize eval 反序列化负载，可执行任意代码 (CVE-2017-5941)",
                                "改用 JSON.parse 等安全反序列化"))
    return findings
