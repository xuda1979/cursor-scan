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

