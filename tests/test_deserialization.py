"""Regression tests for unsafe-deserialization detection (deser.pickle).

``jsonpickle.loads`` is the modern wrapper around pickle with the identical
code-execution surface (it falls back to pickle for nested objects); the
regex fallback previously covered pickle/cPickle/marshal only, so a
jsonpickle load escaped detection entirely.  These tests pin the extension
and keep the existing pickle forms sounding.
"""

from __future__ import annotations

from cursorscan.rules.deserialization import analyze_code


def _py(code: str):
    return [(f.rule_id, f.severity) for f in analyze_code("x.py", code)]


class TestJsonpickleDeserialization:
    def test_jsonpickle_loads_flags(self):
        assert _py("obj = jsonpickle.loads(payload)\n") == [
            ("deser.pickle", "critical")]

    def test_jsonpickle_load_flags(self):
        assert _py("obj = jsonpickle.load(payload)\n") == [
            ("deser.pickle", "critical")]

    def test_jsonpickle_import_line_is_quiet(self):
        # `import jsonpickle` alone is not a load; no finding.
        assert _py("import jsonpickle\n") == []

    def test_dotted_jsonpickle_like_other_libs_is_quiet(self):
        # Not the jsonpickle module -- an unrelated load call.
        assert _py("json.loads(payload)\n") == []

    def test_jsonpickle_encode_is_quiet(self):
        # Serializing out is not a deserialization sink.
        assert _py("data = jsonpickle.encode(obj)\n") == []


class TestPickleFormsStillFlag:
    def test_pickle_loads_flags(self):
        assert _py("x = pickle.loads(data)\n") == [("deser.pickle", "critical")]

    def test_cpickle_load_flags(self):
        assert _py("x = cPickle.load(data)\n") == [("deser.pickle", "critical")]

    def test_cloudpickle_loads_flags(self):
        # cloudpickle is a pickle-family loader with the same execution surface.
        assert _py("obj = cloudpickle.loads(payload)\n") == [("deser.pickle", "critical")]

    def test_dill_load_flags(self):
        assert _py("obj = dill.load(data)\n") == [("deser.pickle", "critical")]

    def test_finding_carries_dimension_and_fix(self):
        found = analyze_code("x.py", "jsonpickle.loads(payload)\n")
        assert found[0].dimension == "deserialization"
        assert found[0].message and found[0].fix


class TestPickleBackedVariants:
    """pickle-backed loaders beyond pickle/cPickle: ``_pickle`` (the C
    implementation), scikit-learn's joblib.load, pandas.read_pickle, and
    numpy/torch paths gated on their unsafe-by-default flags. All execute
    arbitrary code during unpickling, so they share the deser.pickle rule."""

    # --- regex fallback (C-implementation / wrappers) ---
    def test__pickle_loads_flags(self):
        assert _py("x = _pickle.loads(data)\n") == [("deser.pickle", "critical")]

    def test__pickle_load_flags(self):
        assert _py("fh = open(p, 'rb')\nx = _pickle.load(fh)\n") == [("deser.pickle", "critical")]

    def test_joblib_load_flags(self):
        assert _py("model = joblib.load(path)\n") == [("deser.pickle", "critical")]

    def test_dotted_joblib_load_flags(self):
        assert _py("model = sklearn.externals.joblib.load(path)\n") == [("deser.pickle", "critical")]

    def test_pandas_read_pickle_flags(self):
        assert _py("df = pandas.read_pickle(file)\n") == [("deser.pickle", "critical")]

    def test_pd_read_pickle_alias_flags(self):
        assert _py("df = pd.read_pickle(file)\n") == [("deser.pickle", "critical")]

    def test_read_pickle_import_line_is_quiet(self):
        assert _py("import pandas\n") == []

    def test_joblib_dump_is_quiet(self):
        # Serializing out is not a deserialization sink.
        assert _py("joblib.dump(model, path)\n") == []

    def test_pandas_to_pickle_is_quiet(self):
        assert _py("df.to_pickle(file)\n") == []

    # --- AST-gated numpy/torch (flag-marker accuracy needs the AST) ---
    def test_np_load_allow_pickle_true_flags(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "np.load(path, allow_pickle=True)\n", finds)
        assert [(f.rule_id, f.severity) for f in finds] == [("deser.pickle", "critical")]

    def test_np_load_without_allow_pickle_is_quiet(self):
        # numpy.load defaults to allow_pickle=False in current NumPy.
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "data = np.load(path)\n", finds)
        assert finds == []

    def test_np_savez_and_savetxt_are_quiet(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "np.savez(path, arr)\nnp.savetxt(path, arr)\n", finds)
        assert finds == []

    def test_torch_load_default_flags(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "ckpt = torch.load(path)\n", finds)
        assert [(f.rule_id, f.severity) for f in finds] == [("deser.pickle", "critical")]

    def test_torch_load_weights_only_true_is_quiet(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "ckpt = torch.load(path, weights_only=True)\n", finds)
        assert finds == []

    def test_torch_load_weights_only_false_flags(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "ckpt = torch.load(path, weights_only=False)\n", finds)
        assert [(f.rule_id, f.severity) for f in finds] == [("deser.pickle", "critical")]

    def test_torch_dynamic_weights_only_flags(self):
        # A runtime value is unverifiable; torch defaults to the unsafe side.
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "ckpt = torch.load(path, weights_only=opts.safe)\n", finds)
        assert [(f.rule_id, f.severity) for f in finds] == [("deser.pickle", "critical")]

    def test_gated_finding_carries_dimension(self):
        from cursorscan.scanners.ast import analyze_python

        finds = []
        analyze_python("x.py", "torch.load(path)\n", finds)
        assert finds[0].dimension == "deserialization"


class TestShelveAndUnpickler:
    """shelve.open opens a pickle-backed store (CWE-502) and pickle.Unpickler
    is the class twin of pickle.load: both execute arbitrary code while
    reading untrusted data. Serializing twins and constructor variants stay
    quiet."""

    def test_shelve_open_flags(self):
        assert _py("db = shelve.open(path)\n") == [("deser.pickle", "critical")]

    def test_shelve_open_writeback_flags(self):
        assert _py("db = shelve.open(path, writeback=True)\n") == [("deser.pickle", "critical")]

    def test_pickle_unpickler_flags(self):
        assert _py("up = pickle.Unpickler(fh)\n") == [("deser.pickle", "critical")]

    def test_unpickler_load_flags_on_same_line(self):
        assert _py("up = pickle.Unpickler(fh); up.load()\n") == [("deser.pickle", "critical")]

    def test__pickle_unpickler_flags(self):
        # The C-implementation Unpickler shares the execution surface.
        assert _py("up = _pickle.Unpickler(fh)\n") == [("deser.pickle", "critical")]

    def test_shelve_import_line_is_quiet(self):
        assert _py("import shelve\n") == []

    def test_pickle_pickler_is_quiet(self):
        # Serializing out is not a deserialization sink.
        assert _py("pk = pickle.Pickler(fh)\n") == []

    def test_shelve_class_constructors_are_quiet(self):
        # Only shelve.open is matched; Shelf/DbfilenameShelf are not opened
        # from a data stream by this idiom.
        assert _py("db = shelve.DbfilenameShelf(path)\ndb2 = shelve.Shelf(d)\n") == []

    def test_from_import_unpickler_is_quiet(self):
        # `from pickle import Unpickler` has no `pickle.Unpickler` dotted
        # form; the call site is indistinguishable from a local class.
        assert _py("from pickle import Unpickler\nup = Unpickler(fh)\n") == []


class TestXxeParsers:
    """Python stdlib XML parsers resolve external entities by default (CWE-611
    XXE): a DOCTYPE can read local files and probe internal hosts. defusedxml
    is the safe replacement and lxml (no external-entity resolution by default)
    stays quiet."""

    def test_elementtree_fromstring_flags(self):
        assert _py("xml.etree.ElementTree.fromstring(data)\n") == [("deser.xxe", "critical")]

    def test_c_elementtree_parse_flags(self):
        assert _py("xml.etree.cElementTree.parse(path)\n") == [("deser.xxe", "critical")]

    def test_minidom_parse_flags(self):
        assert _py("xml.dom.minidom.parse(path)\n") == [("deser.xxe", "critical")]

    def test_minidom_parsestring_flags(self):
        assert _py("xml.dom.minidom.parseString(xml_text)\n") == [("deser.xxe", "critical")]

    def test_pulldom_parse_flags(self):
        assert _py("xml.dom.pulldom.parse(path)\n") == [("deser.xxe", "critical")]

    def test_sax_parse_flags(self):
        assert _py("xml.sax.parse(path, handler)\n") == [("deser.xxe", "critical")]

    def test_sax_make_parser_flags(self):
        assert _py("parser = xml.sax.make_parser()\n") == [("deser.xxe", "critical")]

    def test_expat_parsercreate_flags(self):
        assert _py("parser = xml.parsers.expat.ParserCreate()\n") == [("deser.xxe", "critical")]

    def test_bare_modulename_after_from_import_flags(self):
        # After `from xml.etree import ElementTree` the bare `ElementTree.parse`
        # spelling is the same sink; the import line itself stays quiet.
        assert _py("from xml.etree import ElementTree\n"
                   "root = ElementTree.parse(path)\n") == [("deser.xxe", "critical")]

    def test_bare_minidom_after_from_import_flags(self):
        assert _py("from xml.dom import minidom\n"
                   "doc = minidom.parseString(xml_text)\n") == [("deser.xxe", "critical")]

    def test_import_line_is_quiet(self):
        assert _py("import xml.etree.ElementTree\n") == []

    def test_lxml_is_quiet(self):
        # lxml does not resolve external entities by default.
        assert _py("from lxml import etree\nroot = etree.parse(path)\n") == []

    def test_defusedxml_is_quiet(self):
        # The documented safe replacement must never flag.
        assert _py("import defusedxml.ElementTree as ET\nroot = ET.parse(path)\n") == []

    def test_et_alias_is_quiet(self):
        # `import xml.etree.ElementTree as ET` then `ET.parse` is a known
        # uncovered alias spelling; the dotted form stays quiet.
        assert _py("import xml.etree.ElementTree as ET\nroot = ET.parse(path)\n") == []


class TestXxeXmlAndIterparse:
    """ElementTree.XML() (string constructor) and iterparse() (streaming pull
    parser) are the same DTD-resolving stdlib sinks as parse/fromstring
    (CWE-611). The `ET.` alias spelling stays quiet like the other alias
    forms, since ET is a common alias for safe lxml trees too."""

    def test_fullname_xml_flags(self):
        assert _py("xml.etree.ElementTree.XML(xml_text)\n") == [("deser.xxe", "critical")]

    def test_fullname_c_elementtree_xml_flags(self):
        assert _py("xml.etree.cElementTree.XML(xml_text)\n") == [("deser.xxe", "critical")]

    def test_fullname_iterparse_flags(self):
        assert _py("for e, el in xml.etree.ElementTree.iterparse(path): pass\n") == \
            [("deser.xxe", "critical")]

    def test_bare_elementtree_xml_after_from_import_flags(self):
        assert _py("from xml.etree import ElementTree\nroot = ElementTree.XML(xml_text)\n") == \
            [("deser.xxe", "critical")]

    def test_bare_elementtree_iterparse_after_from_import_flags(self):
        assert _py("from xml.etree import ElementTree\n"
                   "for e, el in ElementTree.iterparse(path): pass\n") == \
            [("deser.xxe", "critical")]

    def test_et_alias_is_quiet(self):
        # Same alias ambiguity as ET.parse: not a fully-qualified sink.
        assert _py("import xml.etree.ElementTree as ET\nroot = ET.XML(xml_text)\n") == []

    def test_elementtree_class_name_is_quiet(self):
        # The class name itself, not a call, and no `(` call.
        assert _py("ElementTree.XML\n") == []


class TestNodeVmRun:
    """Node's vm.runIn*Context executes a source string -- the JS counterpart
    of eval. Dynamic source flags as deser.eval; literals and other vm API
    calls stay quiet."""

    def _js(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.js", code)]

    def test_run_in_this_context_flags(self):
        assert self._js("vm.runInThisContext(expr);\n") == [("deser.eval", "critical")]

    def test_run_in_new_context_flags(self):
        assert self._js("vm.runInNewContext(source);\n") == [("deser.eval", "critical")]

    def test_run_in_context_flags(self):
        assert self._js("vm.runInContext(code, ctx);\n") == [("deser.eval", "critical")]

    def test_required_vm_form_flags(self):
        assert self._js('require("vm").runInThisContext(code);\n') == \
            [("deser.eval", "critical")]

    def test_node_prefix_require_form_flags(self):
        assert self._js('const vm = require("node:vm");\n'
                        'vm.runInNewContext(user);\n') == [("deser.eval", "critical")]

    def test_static_literal_is_quiet(self):
        assert self._js('vm.runInNewContext("1+1");\n') == []

    def test_compile_function_is_quiet(self):
        assert self._js("vm.compileFunction(src, []);\n") == []

    def test_import_line_is_quiet(self):
        assert self._js('import { runInNewContext } from "vm";\n') == []


class TestNodeUnserialize:
    """node-serialize's unserialize() eval-deserializes its payload
    (CVE-2017-5941): any non-literal payload is arbitrary code execution, the
    JS counterpart of pickle. Dynamic payloads flag as deser.pickle; the
    serialize() writer and static payloads stay quiet."""

    def _js(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.js", code)]

    def test_bare_unserialize_flags(self):
        assert self._js("unserialize(payload);\n") == [("deser.pickle", "critical")]

    def test_dotted_unserialize_flags(self):
        assert self._js("serialize.unserialize(userBlob);\n") == \
            [("deser.pickle", "critical")]

    def test_destructured_require_form_flags(self):
        assert self._js('const { unserialize } = require("node-serialize");\n'
                        "const obj = unserialize(req.body.data);\n") == \
            [("deser.pickle", "critical")]

    def test_static_literal_is_quiet(self):
        assert self._js('serialize.unserialize("{\\"x\\":1}");\n') == []

    def test_template_literal_with_interp_flags(self):
        assert self._js('serialize.unserialize(`{"_$$ND_FUNC$$_${fn}"}`);\n') == \
            [("deser.pickle", "critical")]

    def test_serialize_writer_is_quiet(self):
        assert self._js("serialize.serialize(obj);\n") == []


class TestYamlLoaderSelection:
    """yaml.load produces its loader through the Loader keyword. The only
    safe families are Safe/Base/Full (FullLoader being PyYAML 5.1+'s safe
    default); bare ``yaml.load``, the Loader alias, and UnsafeLoader /
    CUnsafeLoader all construct arbitrary Python objects (CWE-502)."""

    def _py(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.py", code)]

    def test_plain_load_flags(self):
        assert self._py("yaml.load(text)\n") == [("deser.yaml_load", "critical")]

    def test_load_all_flags(self):
        assert self._py("yaml.load_all(stream)\n") == [("deser.yaml_load", "critical")]

    def test_unsafe_load_flags(self):
        assert self._py("yaml.unsafe_load(text)\n") == [("deser.yaml_load", "critical")]

    def test_explicit_unsafe_loader_flags(self):
        # Previously suppressed by the "UnsafeLoader" exclusion: an explicit
        # unsafe loader is the provably worst form and must flag.
        assert self._py("yaml.load(text, Loader=yaml.UnsafeLoader)\n") == \
            [("deser.yaml_load", "critical")]

    def test_bare_loader_alias_flags(self):
        assert self._py("yaml.load(text, Loader=Loader)\n") == \
            [("deser.yaml_load", "critical")]

    def test_cunsafe_loader_flags(self):
        assert self._py("yaml.load(text, Loader=yaml.CUnsafeLoader)\n") == \
            [("deser.yaml_load", "critical")]

    def test_safe_loader_quiet(self):
        assert self._py("yaml.load(text, Loader=yaml.SafeLoader)\n") == []

    def test_csafe_loader_quiet(self):
        assert self._py("yaml.load(text, Loader=yaml.CSafeLoader)\n") == []

    def test_base_loader_quiet(self):
        assert self._py("yaml.load(text, Loader=yaml.BaseLoader)\n") == []

    def test_full_loader_quiet(self):
        # FullLoader is the documented safe default for untrusted input.
        assert self._py("yaml.load(text, Loader=yaml.FullLoader)\n") == []

    def test_safe_load_quiet(self):
        assert self._py("yaml.safe_load(text)\n") == []


class TestRubyMarshal:
    """Ruby's Marshal.load/restore unpickle a serialized object graph into
    arbitrary live objects (CWE-502) -- the Ruby counterpart of pickle.
    The dump writer direction and a bare ``load`` stay quiet."""

    def _rb(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.rb", code)]

    def test_load_flags(self):
        assert self._rb("Marshal.load(data)\n") == [("deser.pickle", "critical")]

    def test_restore_alias_flags(self):
        assert self._rb("Marshal.restore(File.binread(path))\n") == \
            [("deser.pickle", "critical")]

    def test_fully_qualified_const_flags(self):
        assert self._rb("::Marshal.load(blob)\n") == [("deser.pickle", "critical")]

    def test_dump_writer_is_quiet(self):
        assert self._rb("Marshal.dump(obj)\n") == []

    def test_bare_load_is_quiet(self):
        # Without the Marshal receiver this is a plain method call.
        assert self._rb("load(data)\n") == []


class TestRubyYamlUnsafe:
    """Ruby's Psych >= 4 made plain loading safe by default; the explicit
    unsafe_load is the arbitrary-object constructor (CWE-502), the same sink
    family as Python's yaml.load rule."""

    def _rb(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.rb", code)]

    def test_yaml_unsafe_load_flags(self):
        assert self._rb("YAML.unsafe_load(text)\n") == [("deser.yaml_load", "critical")]

    def test_psych_unsafe_load_flags(self):
        assert self._rb("Psych.unsafe_load(text)\n") == [("deser.yaml_load", "critical")]

    def test_lowercase_yaml_unsafe_load_flags(self):
        assert self._rb("yaml.unsafe_load(text)\n") == [("deser.yaml_load", "critical")]

    def test_plain_yaml_load_is_quiet(self):
        # Psych >= 4 default is safe loading; YAML.load is not the unsafe sink.
        assert self._rb("YAML.load(text)\n") == []

    def test_safe_load_is_quiet(self):
        assert self._rb("YAML.safe_load(text)\n") == []


class TestJavaDeser:
    """Java native deserialization: readObject/readUnshared reconstruct
    arbitrary objects, and XMLDecoder instantiates arbitrary classes from an
    XML document (CWE-502). A static-literal or class-name argument is inert;
    an empty call or a variable argument is an untrusted data stream."""

    def _java(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("X.java", code)]

    def test_readobject_noarg_flags(self):
        assert self._java("return ois.readObject();\n") == [("deser.pickle", "critical")]

    def test_readobject_dynamic_arg_flags(self):
        assert self._java("return ois.readObject(stream);\n") == \
            [("deser.pickle", "critical")]

    def test_readobject_static_string_literal_is_quiet(self):
        # "CONFIG" is inert content, not an untrusted data stream.
        assert self._java('return ois.readObject("CONFIG");\n') == []

    def test_readobject_class_name_arg_is_quiet(self):
        assert self._java("return ois.readObject(String.class);\n") == []

    def test_read_unshared_flags(self):
        assert self._java("return ois.readUnshared();\n") == [("deser.pickle", "critical")]

    def test_xml_decoder_flags(self):
        assert self._java("XMLDecoder dec = new XMLDecoder(in);\n") == \
            [("deser.pickle", "critical")]

    def test_object_input_stream_ctor_is_quiet(self):
        # Constructing the stream does not deserialize.
        assert self._java("ObjectInputStream ois = new ObjectInputStream(in);\n") == []

    def test_bare_method_without_dot_is_quiet(self):
        # The regex requires the dotted receiver form.
        assert self._java("return readObject();\n") == []


class TestPhpUnserialize:
    """PHP unserialize() reconstructs arbitrary PHP objects from a payload
    (CWE-502), the same sink family as node-serialize's unserialize. The
    serialize() writer direction stays quiet."""

    def _php(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.php", code)]

    def test_unserialize_var_flags(self):
        assert self._php("$obj = unserialize($payload);\n") == \
            [("deser.pickle", "critical")]

    def test_unserialize_literal_is_quiet(self):
        assert self._php('unserialize("O:1:...")\n') == []

    def test_serialize_writer_is_quiet(self):
        assert self._php("$data = serialize($obj);\n") == []


class TestPhpXxe:
    """PHP's libxml-based sinks resolve external entities by default (CWE-611
    XXE): simplexml_load_*, DOMDocument->loadXML/load, and xml_parse with a
    fresh parser execute DTD external-entity reads unless opted out via
    libxml_disable_entity_loader / LIBXML_NONET (rare and itself a review
    signal). Bookkeeping calls like libxml_use_internal_errors are not loads."""

    def _php(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("x.php", code)]

    def test_simplexml_load_string_flags(self):
        assert self._php("return simplexml_load_string($raw);\n") == \
            [("deser.xxe", "critical")]

    def test_simplexml_load_file_flags(self):
        assert self._php("return simplexml_load_file($path);\n") == \
            [("deser.xxe", "critical")]

    def test_dom_loadxml_flags(self):
        assert self._php("$doc = new DOMDocument();\n$doc->loadXML($raw);\n") == \
            [("deser.xxe", "critical")]

    def test_dom_load_flags(self):
        assert self._php("$doc = new DOMDocument();\n$doc->load($path);\n") == \
            [("deser.xxe", "critical")]

    def test_xml_parse_with_parser_create_flags(self):
        assert self._php("xml_parse(xml_parser_create(), $raw);\n") == \
            [("deser.xxe", "critical")]

    def test_libxml_use_internal_errors_is_quiet(self):
        # Bookkeeping, not a document load; reported by a featurized scan only
        # when a load sink is present.
        assert self._php("libxml_use_internal_errors(true);\n") == []

    def test_non_xml_load_is_quiet(self):
        # Database/asset loaders are not XML sinks.
        assert self._php("$db->load($path);\n") == []

    def test_php_xxe_finding_carries_dimension(self):
        found = analyze_code("x.php", "simplexml_load_file($f);\n")
        assert found[0].dimension == "deserialization"


class TestJavaXxe:
    """Java's XML factory sinks resolve external DTDs unless the well-known
    FEATURE_SECURE_PROCESSING / external-entity disablers are set (CWE-611):
    DocumentBuilderFactory / SAXParserFactory / TransformerFactory /
    XMLInputFactory / SchemaFactory built via newInstance()/newFactory()."""

    def _java(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("X.java", code)]

    def test_document_builder_factory_flags(self):
        assert self._java("DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n") == \
            [("deser.xxe", "critical")]

    def test_sax_parser_factory_flags(self):
        assert self._java("SAXParserFactory spf = SAXParserFactory.newInstance();\n") == \
            [("deser.xxe", "critical")]

    def test_xml_input_factory_new_factory_flags(self):
        # newFactory() is the standard spelling for XMLInputFactory.
        assert self._java("XMLInputFactory xif = XMLInputFactory.newFactory();\n") == \
            [("deser.xxe", "critical")]

    def test_transformer_factory_flags(self):
        assert self._java("TransformerFactory tf = TransformerFactory.newInstance();\n") == \
            [("deser.xxe", "critical")]

    def test_schema_factory_flags(self):
        assert self._java('SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);\n') == \
            [("deser.xxe", "critical")]

    def test_secure_processing_guard_offsets_sink(self):
        # Setting FEATURE_SECURE_PROCESSING + disabling external DTDs is the
        # fix; a builder line that only constructs the factory still flags for
        # review (the negligible-protection form is out of scope here).
        assert len(self._java("DocumentBuilderFactory.newInstance();\n")) == 1


class TestJavaJacksonTyping:
    """Jackson's default typing embeds polymorphic @class metadata that Jackson
    instantiates on deserialization (CWE-502), the Java counterpart of
    readObject. enableDefaultTyping/activateDefaultTyping flag; the disable
    forms switch bundling OFF and stay quiet, and shutdown-overwrite calls are
    not leaks."""

    def _java(self, code: str):
        return [(f.rule_id, f.severity) for f in analyze_code("X.java", code)]

    def test_enable_default_typing_flags(self):
        assert self._java("mapper.enableDefaultTyping();\n") == \
            [("deser.pickle", "critical")]

    def test_activate_default_typing_flags(self):
        assert self._java("om.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL);\n") == \
            [("deser.pickle", "critical")]

    def test_config_line_forward_declaration_flags(self):
        # The dotted call with arguments still flags; only OFF switches are
        # treated as safe configuration.
        assert self._java("ObjectMapper om = new ObjectMapper();\n"
                          "om.activateDefaultTyping(ptv);\n") == \
            [("deser.pickle", "critical")]

    def test_disable_default_typing_is_quiet(self):
        # Switching the feature off is the mitigation, not the vulnerability.
        assert self._java("mapper.disableDefaultTyping();\n") == []

    def test_deactivate_default_typing_is_quiet(self):
        # Alias of the OFF switch for the activate() counterpart.
        assert self._java("ObjectMapper om = new ObjectMapper();\n"
                          "om.deactivateDefaultTyping();\n") == []

