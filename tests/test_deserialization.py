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

    def test_finding_carries_dimension_and_fix(self):
        found = analyze_code("x.py", "jsonpickle.loads(payload)\n")
        assert found[0].dimension == "deserialization"
        assert found[0].message and found[0].fix
