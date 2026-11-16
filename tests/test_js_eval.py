"""Regression tests for JS ``new Function(...)`` (deser.eval) detection.

tree-sitter models ``new Function(body)`` as a ``new_expression`` node, never
as a ``call_expression``, so the call-walker never saw it: the old
``"new Function"`` entry in the eval branch was dead code and ``Function``
constructor injection escaped detection entirely. These tests pin the fixed
behavior -- external input through the Function constructor is flagged, while
static-string bodies and unrelated constructors stay quiet.
"""

from __future__ import annotations

from cursorscan.scanners.ast import analyze_jsts


def _js(code: str, name: str = "x.js"):
    finds = []
    analyze_jsts(name, code, finds)
    return finds


class TestNewFunctionInjection:
    def test_identifier_body_flags(self):
        finds = _js("const f = new Function(userInput)\n")
        assert [(f.rule_id, f.severity) for f in finds] == [
            ("deser.eval", "critical")]

    def test_request_body_flags(self):
        finds = _js("new Function(req.body.code)\n")
        assert [(f.rule_id, f.line) for f in finds] == [("deser.eval", 1)]

    def test_process_env_flags_in_ts(self):
        finds = _js("const t: any = new Function(process.env.SCRIPT)\n", "x.ts")
        assert [(f.rule_id, f.severity) for f in finds] == [
            ("deser.eval", "critical")]

    def test_static_string_body_is_quiet(self):
        # A literal body is not external input; not provably unsafe.
        finds = _js("const g = new Function('return 1')\n")
        assert finds == []

    def test_other_constructors_are_quiet(self):
        finds = _js("const d = new Date()\n"
                    "const e = new Error('boom')\n"
                    "const r = new RegExp(userInput)\n")
        assert finds == []

    def test_finding_carries_metadata(self):
        finds = _js("const f = new Function(input)\n")
        assert finds[0].dimension == "deserialization"
        assert finds[0].rule_id == "deser.eval"
        assert "Function 构造器" in finds[0].fix


class TestEvalStillFlags:
    """Sibling eval() path must keep working alongside the new pass."""

    def test_bare_eval_flags(self):
        finds = _js("eval(req.body.code)\n")
        assert [(f.rule_id, f.line) for f in finds] == [("deser.eval", 1)]

    def test_eval_and_function_both_found(self):
        finds = _js("eval(req.body.code)\nconst f = new Function(userInput)\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("deser.eval", 1), ("deser.eval", 2)]
