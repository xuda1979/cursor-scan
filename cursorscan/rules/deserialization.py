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
    # Python (yaml.unsafe_load) plus Ruby: YAML.unsafe_load / Psych.unsafe_load
    # (Psych >= 4 made the plain safe-loading default; unsafe_load is the
    # explicit arbitrary-object constructor in both ecosystems).
    r"\b(?:yaml|YAML|Psych)\.unsafe_load\b"
)
RE_YAML_LOAD = re.compile(
    r"\b(yaml\.load|yaml\.load_all)\s*\(.*"
)
# The only loader families that refuse to build arbitrary Python objects:
# (C)?(Safe|Base)Loader by construction, and (C)?FullLoader which PyYAML 5.1+
# made the safe default for yaml.load.  The bare Loader alias (PyYAML < 5.1
# default), UnsafeLoader, and CUnsafeLoader all construct arbitrary Python
# objects and are explicitly dangerous.
RE_YAML_SAFE_LOADER = re.compile(
    r"(?:yaml\.)?C?(?:Safe|Base|Full)Loader",
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
# Ruby's Marshal: ``Marshal.load`` / ``Marshal.restore`` (alias) unpickle a
# serialized object graph into arbitrary live objects -- the Ruby counterpart
# of Python pickle (CWE-502).  Full constant qualification ``::Marshal`` is
# accepted too; the Marshal.dump / Marshal.dump_to_file writer direction and
# a bare ``load`` without the Marshal receiver stay quiet.
RE_RUBY_MARSHAL = re.compile(
    r"""\b(?:::)?Marshal\.(?:load|restore)\s*\(""",
)
# Java's native-serialization and XML-decoder sinks (CWE-502): readObject /
# readUnshared on an ObjectInputStream reconstruct arbitrary objects, and
# XMLDecoder instantiates arbitrary Java classes from an XML document. A
# static literal argument is inert XML/schema content; an empty call (the
# classic ``ois.readObject()``) or a variable/expression is an untrusted data
# stream. Merely constructing an ObjectInputStream does not deserialize, so
# the new-... constructor line stays quiet.
RE_JAVA_READOBJ = re.compile(
    r"""\.read(?:Object|Unshared)\s*\(\s*([^)"']*?)\s*\)""",
)
_REAJAVA_STATIC_ARG = re.compile(
    r"""^(?:[A-Za-z_$][\w$]*\.)*[A-Z][\w$]*\s*(?:\.class)?$""",
)
RE_JAVA_XMLDECODER = re.compile(
    r"""\bXMLDecoder\s*\(""",
)
# node-serialize's unserialize() deserializes a serialized function graph by
# eval'ing the payload (CVE-2017-5941): any non-literal payload is arbitrary
# code execution, the JS counterpart of Python pickle. PHP's unserialize()
# reconstructs arbitrary PHP objects the same way (CWE-502), so the same
# sink family covers both. The matching writer directions (serialize() /
# node-serialize's serialize(), PHP's serialize()) and a bare static literal
# stay quiet.
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
        elif RE_YAML_LOAD.search(raw) and not RE_YAML_SAFE_LOADER.search(raw):
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
        # Ruby Marshal: load/restore unpickle an object graph into live objects.
        if RE_RUBY_MARSHAL.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Marshal)",
                                "Marshal.load/restore 反序列化 Ruby 对象图，可执行任意代码",
                                "改用安全的文本格式 (JSON/YAML load_serializable)"))
        # Java native deserialization: recursive data reconstruction, the
        # classic "trampoline" gadget chain (CWE-502). A static-literal
        # argument (document/class-name/schema constant) is inert; an empty
        # readObject() or a variable argument is an untrusted data stream.
        if m := RE_JAVA_READOBJ.search(raw):
            arg = m.group(1).strip()
            if not arg or not _REAJAVA_STATIC_ARG.search(arg):
                findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Java)",
                                    "readObject/readUnshared 反序列化不受信数据流，",
                                    "对输入做签名校验并限制 gadget 类 (ObjectInputFilter)"))
        # XMLDecoder instantiates arbitrary Java classes from an XML document --
        # immediate class instantiation, not just object reconstruction.
        if RE_JAVA_XMLDECODER.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Java)",
                                "XMLDecoder 从 XML 实例化任意 Java 类",
                                "改用安全的解析器 (StAX/SAX) 并验证 DTD/类型"))
        if RE_NODE_UNSERIALIZE.search(raw):
            findings.append(hit(lineno, "deser.pickle", "unserialize 反序列化",
                                "unserialize 反序列化负载并重建对象，可执行任意代码 (CVE-2017-5941)",
                                "改用 JSON.parse 等安全反序列化"))
    return findings
