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
# Keras load_model reads a serialized model archive: the .keras zip format
# embeds pickled objects and the legacy .h5 container reconstructs custom
# objects from metadata, so an untrusted model is arbitrary code execution
# during loading (CWE-502), the ML-ecosystem counterpart of joblib.load.
# There is no safe-flag counterpart, so any load_model call flags (joblib
# precedent). Covers plain and tf.keras qualifications of the classic
# keras.models entry point and the Keras-3 keras.saving home.
RE_KERAS_LOAD_MODEL = re.compile(
    r"\b(?:tf\.)?keras\.(?:models|saving)\.load_model\s*\(",
)
# Keras load_model reads a serialized model archive: the .keras zip format
# embeds pickled objects and the legacy .h5 container also reconstructs
# custom objects through the config, and Keras' own docs warn that loading an
# untrusted model can execute arbitrary code (CWE-502) -- the ML-ecosystem
# twin of joblib.load.  There is no safe-flag counterpart, so any load_model
# call flags.  Covers the classic keras.models entry point and the Keras 3
# keras.saving home, plus both plain and tf.keras qualification.
RE_KERAS_LOAD_MODEL = re.compile(
    r"\b(?:tf\.)?keras\.(?:models|saving)\.load_model\s*\(",
)
# Python stdlib XML parsers resolve external entities by default (CWE-611
# XXE): xml.etree / xml.dom / xml.sax / xml.parsers.expat all let a document's
# DOCTYPE read local files and probe internal hosts during parsing. defusedxml
# is the safe replacement; lxml does not resolve external entities by default
# and stays quiet. Both the fully-qualified spellings (xml.etree.ElementTree.
# parse) and the bare module names (minidom / pulldom / ElementTree after a
# from-import) are covered.
RE_XML_PARSE = re.compile(
    r"\b(?:xml\.etree\.(?:c?ElementTree)\.(?:parse|fromstring|XML|iterparse)"
    r"|xml\.dom\.minidom\.(?:parse|parseString)"
    r"|xml\.dom\.pulldom\.(?:parse|parseString)"
    r"|xml\.sax\.(?:parse|parseString|make_parser)"
    r"|xml\.parsers\.expat\.ParserCreate"
    r"|ElementTree\.(?:parse|fromstring|XML|iterparse)"
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
# PHP's libxml-based XML sinks (CWE-611 XXE): simplexml loaders, DOMDocument
# loadXML/load, and xml_parse() all resolve external entities (unless
# libxml_disable_entity_loader / LIBXML_NONET were opted in, which is rare and
# itself a review signal). DOMDocument instances are held in variables, so the
# receiver form is matched: ``->loadXML`` is DOMDocument-specific and always
# an XML load; a bare ``->load`` additionally requires a document-hinted
# receiver ($dom/$doc/$document/$xml...), keeping generic database/asset
# loaders (``$db->load``) quiet. The libxml_use_internal_errors() bookkeeping
# calls are not document loads and stay quiet.
RE_PHP_XXE = re.compile(
    r"(?:simplexml_load_(?:file|string)"
    r"|\$\w+\s*->\s*loadXML"
    r"|\$(?:dom|doc|document|xml)\w*\s*->\s*load"
    r"|xml_parse\s*\(\s*xml_parser_create)\s*\(",
)
# Java's XML factory sinks (CWE-611 XXE): DocumentBuilderFactory / SAXParser
# Factory / TransformerFactory / XMLInputFactory / SchemaFactory built with
# newInstance()/newFactory() parse DTDs that can read local files unless the
# well-known FEATURE_SECURE_PROCESSING / external-DTD settings are explicitly
# applied. The builder objects themselves are the sink root -- .parse(...)
# calls made on them later are the same object and need no separate rule.
RE_JAVA_XXE = re.compile(
    r"\b(?:DocumentBuilderFactory|SAXParserFactory|TransformerFactory"
    r"|XMLInputFactory|SchemaFactory)\s*\.(?:newInstance|newFactory)\s*\(",
)
# .NET's XML sink family (CWE-611 XXE): XmlDocument.Load/LoadXml, XDocument/
# XElement.Parse/Load, XmlReader.Create and XmlTextReader all resolve DTD
# external entities during parsing, which lets a crafted document read local
# files and probe internal hosts (classic "billion laughs" / file-read XXE).
# Typed receiver names are unambiguous XML loads and always match (the
# XmlDocument.LoadXml / XDocument.Parse / XmlReader.Create call shapes); a
# bare .Load form additionally requires a document-hinted receiver
# (doc/document/xml...), keeping generic database/asset loaders
# (``db.Load``) quiet -- mirroring the PHP DOMDocument gate. C# APIs are
# conventionally capitalized, so the pattern is case-sensitive by design.
RE_DOTNET_XXE = re.compile(
    r"\b(?:XmlDocument\.(?:LoadXml|Load)"
    r"|X(?:Document|Element)\.(?:Parse|Load)"
    r"|XmlReader\.Create|XmlTextReader)\s*\("
    r"|\b(?:doc|document|xml)\w*\s*\.\s*(?:LoadXml|Load)\s*\(",
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
# Jackson's default typing embeds polymorphic type metadata in `@class`
# properties that Jackson instantiates on deserialization (CWE-502): a
# crafted payload for enableDefaultTyping/activateDefaultTyping becomes
# arbitrary class instantiation, the Java counterpart of readObject.
# disableDefaultTyping()/deactivateDefaultTyping() switch the feature OFF and
# stay quiet.
RE_JAVA_JACKSON_TYPING = re.compile(
    r"\.(?:enableDefaultTyping|activateDefaultTyping)\s*\(",
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
# SnakeYAML (Java) load-family sinks (CWE-502): yaml.load / loadAll / loadAs
# instantiate arbitrary Java classes from YAML tags unless a safe-constructor
# policy is applied -- the Java counterpart of Python yaml.load / Ruby
# unsafe_load.  The lowercase `yaml` matches the natural Java variable name
# (`Yaml yaml = new Yaml();`), and the capitalized `Yaml` covers a
# static-call style; because both spellings overlap the Python/Ruby
# lowercase-module rules, this pattern and the Python/Ruby yaml branches are
# mutually gated on source extension in analyze_code (this one fires only in
# .java files, the others only outside them).  The explicit safe-loader
# opt-outs (constructor for SafeConstructor / SafeLoader / LoaderOptions)
# switch arbitrary-object building OFF and stay quiet, mirroring
# RE_YAML_SAFE_LOADER.  The dump() writer direction is quiet.
RE_JAVA_YAML_LOAD = re.compile(
    r"\b[yY]aml\s*\.\s*(?:load|loadAll|loadAs)\s*\(",
)
RE_JAVA_YAML_SAFE_LOADER = re.compile(
    r"(?:SafeConstructor|SafeLoader|LoaderOptions)\s*\)",
)
# XStream fromXML (CWE-502): fromXML() builds live objects from an XML
# document -- the Java XML-object-graph counterpart of readObject, historically
# the classic remote-code-execution gadget family (CVE-2013-7285 and friends).
# The toXML() / toXML(out, obj) writer directions stay quiet.
RE_JAVA_XSTREAM_FROMXML = re.compile(
    r"\.fromXML\s*\(",
)
# Kryo readClassAndObject (CWE-502): reads a serialized object graph built
# from a runtime type registration -- a registered gadget class becomes an
# arbitrary object.  Only readClassAndObject gets its own rule here; Kryo's
# plain readObject spelling already fires under RE_JAVA_READOBJ's dynamic-arg
# gate (Kryo's readObject(Output, Type) always carries a type argument, which
# that gate treats as dynamic).  The writeClassAndObject / writeObject writer
# directions stay quiet.
RE_JAVA_KRYO_READ = re.compile(
    r"\.readClassAndObject\s*\(",
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity="critical", file=source_path,
                        line=line, message=msg, fix=fix, dimension="deserialization")

    # The Jackson default-typing rule is Java-specific; like injection.py, the
    # .java extension gate keeps it from mis-firing on other languages that
    # happen to call a same-named method.
    ext = source_path.rsplit(".", 1)[-1].lower() if "." in source_path else ""

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
        # Keras load_model reconstructs a serialized model archive (pickled
        # objects in the .keras zip, custom-object config in .h5): an
        # untrusted model is arbitrary code execution (CWE-502), like joblib.
        if RE_KERAS_LOAD_MODEL.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Keras)",
                                "load_model 读取序列化模型存档，加载不可信模型可执行任意代码",
                                "仅加载受信任、经过校验的模型，或使用安全导出格式"))
        if RE_XML_PARSE.search(raw):
            findings.append(hit(lineno, "deser.xxe", "XXE 外部实体注入",
                                "stdlib XML 解析默认解析外部实体，可读取本地文件/内网探测",
                                "改用 defusedxml 或禁用 DTD/外部实体"))
        # Python (lowercase yaml) and Ruby (YAML/Psych) loader branches are
        # owned outside .java files: in Java sources the same lowercase text
        # is a SnakeYAML variable receiver handled by RE_JAVA_YAML_LOAD, so
        # the extension gate keeps each convention single-fire.
        if ext != "java" and RE_YAML_UNSAFE.search(raw):
            findings.append(hit(lineno, "deser.yaml_load", "不安全 yaml.load",
                                "yaml.unsafe_load 可执行任意代码", "yaml.safe_load(data)"))
        elif ext != "java" and RE_YAML_LOAD.search(raw) and not RE_YAML_SAFE_LOADER.search(raw):
            findings.append(hit(lineno, "deser.yaml_load", "不安全 yaml.load",
                                "yaml.load 需要显式安全 Loader (SafeLoader)", "yaml.safe_load(data)"))
        if RE_PHP_XXE.search(raw):
            findings.append(hit(lineno, "deser.xxe", "XXE 外部实体注入",
                                "PHP libxml 解析默认解析外部实体，可读取本地文件/内网探测",
                                "libxml_disable_entity_loader(true) 或使用 LIBXML_NONET"))
        if RE_JAVA_XXE.search(raw):
            findings.append(hit(lineno, "deser.xxe", "XXE 外部实体注入",
                                "Java XML 解析器默认解析 DTD 外部实体，可读取本地文件/内网探测",
                                "设置 FEATURE_SECURE_PROCESSING 并禁用 external DTD"))
        # .NET XML sinks (C#): a document-hinted receiver rule keeps the typed
        # and bare forms single-fire. The extension gate mirrors the Java-only
        # gates above -- the receiver spellings (doc.Load / xml.Load) are not
        # C#-exclusive text and must not fire in other languages.
        if ext == "cs" and RE_DOTNET_XXE.search(raw):
            findings.append(hit(lineno, "deser.xxe", "XXE 外部实体注入",
                                ".NET XML 解析默认解析 DTD 外部实体，可读取本地文件/内网探测",
                                "设置 XmlResolver = null / XmlReaderSettings 禁用 DTD 与外部实体"))
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
        # Jackson default typing: @class metadata drives polymorphic type
        # instantiation on deserialization.  Only meaningful in Java sources.
        if ext == "java" and RE_JAVA_JACKSON_TYPING.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Jackson)",
                                "enableDefaultTyping/activateDefaultTyping 反序列化类型元数据可实例化任意类",
                                "为 @class 属性配置 allowlist 或关闭默认类型绑定"))
        # SnakeYAML load family: arbitrary class instantiation via YAML tags.
        if ext == "java" and RE_JAVA_YAML_LOAD.search(raw) and not \
                RE_JAVA_YAML_SAFE_LOADER.search(raw):
            findings.append(hit(lineno, "deser.yaml_load", "不安全反序列化 (SnakeYAML)",
                                "Yaml.load/loadAll/loadAs 可从 YAML 标签实例化任意 Java 类",
                                "使用 SafeConstructor/SafeLoader 构造 Yaml"))
        # XStream fromXML: live objects built from an XML document (the classic
        # Java RCE gadget family).  Only meaningful in Java sources.
        if ext == "java" and RE_JAVA_XSTREAM_FROMXML.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (XStream)",
                                "fromXML 从 XML 构建反序列化对象图，可实例化任意 Java 类",
                                "配置 XStream 白名单/黑名单 (setupSecurity) 或改用安全解析器"))
        # Kryo readClassAndObject / readObject: runtime-registered gadget class
        # becomes an arbitrary object.  Only meaningful in Java sources.
        if ext == "java" and RE_JAVA_KRYO_READ.search(raw):
            findings.append(hit(lineno, "deser.pickle", "不安全反序列化 (Kryo)",
                                "readClassAndObject/readObject 反序列化 Kryo 对象图，可实例化任意类",
                                "使用内置序列化器白名单并校验注册类"))
        if RE_NODE_UNSERIALIZE.search(raw):
            findings.append(hit(lineno, "deser.pickle", "unserialize 反序列化",
                                "unserialize 反序列化负载并重建对象，可执行任意代码 (CVE-2017-5941)",
                                "改用 JSON.parse 等安全反序列化"))
    return findings
