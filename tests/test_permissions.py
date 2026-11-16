"""Regression tests for insecure-permission detection (perms.*).

Two coverage holes pinned here: the keyword-form ``mode=`` spellings of the
world-writable chmod/mkdir calls (the positional-only regexes let
``os.chmod(path, mode=0o666)`` escape entirely), and ``tempfile.mktemp``
(CWE-377), whose predictable temp path is the exact anti-pattern the
``/tmp`` fix text recommends replacing with mkstemp.  Safe modes, atomic
tempfile APIs, and static-only reads stay quiet.
"""

from __future__ import annotations

from cursorscan.rules.permissions import analyze_code


def _py(code: str):
    return [(f.rule_id, f.severity) for f in analyze_code("x.py", code)]


class TestChmodWordWritable:
    def test_positional_777_flags(self):
        assert _py("os.chmod(path, 0o777)\n") == [("perms.chmod_world_writable", "high")]

    def test_positional_666_flags(self):
        assert _py("os.chmod(path, 0o666)\n") == [("perms.chmod_world_writable", "high")]

    def test_keyword_mode_777_flags(self):
        # The regression this class guards: previously positional-only.
        assert _py("os.chmod(path, mode=0o777)\n") == [("perms.chmod_world_writable", "high")]

    def test_keyword_mode_666_flags(self):
        assert _py("os.chmod(path, mode=0o666)\n") == [("perms.chmod_world_writable", "high")]

    def test_safe_keyword_mode_quiet(self):
        assert _py("os.chmod(path, mode=0o600)\n") == []

    def test_safe_positional_mode_quiet(self):
        assert _py("os.chmod(path, 0o644)\n") == []

    def test_symbolic_mode_quiet(self):
        # stat.S_IRWXU is a variable, not the literal 0777/0666.
        assert _py("os.chmod(path, stat.S_IRWXU)\n") == []


class TestMkdirWorldWritable:
    def test_keyword_777_flags(self):
        assert _py("os.makedirs(path, mode=0o777)\n") == [("perms.world_writable_dir", "high")]

    def test_keyword_666_flags(self):
        # Consistency: 0666 dirs are world-writable just like 0777.
        assert _py("os.makedirs(path, mode=0o666)\n") == [("perms.world_writable_dir", "high")]

    def test_positional_777_flags(self):
        assert _py("os.makedirs(path, 0o777)\n") == [("perms.world_writable_dir", "high")]

    def test_private_mode_quiet(self):
        assert _py("os.makedirs(path, mode=0o700)\n") == []

    def test_default_mode_quiet(self):
        # os.makedirs default mode is 0o777 but is masked by the umask and is
        # the documented default; a bare call is not provably a mistake.
        assert _py("os.makedirs(path)\n") == []


class TestMktempUnsafe:
    def test_mktemp_flags(self):
        assert _py("tmp = tempfile.mktemp()\n") == [("perms.mktemp_unsafe", "high")]

    def test_mktemp_with_prefix_flags(self):
        assert _py("tmp = tempfile.mktemp(prefix='app-')\n") == [("perms.mktemp_unsafe", "high")]

    def test_mkstemp_quiet(self):
        # The safe replacement: atomic create with 0o600.
        assert _py("fd, path = tempfile.mkstemp()\n") == []

    def test_mkdtemp_quiet(self):
        assert _py("path = tempfile.mkdtemp()\n") == []

    def test_named_temporary_file_quiet(self):
        assert _py("f = tempfile.NamedTemporaryFile()\n") == []

    def test_import_line_is_quiet(self):
        assert _py("import tempfile\n") == []

    def test_finding_carries_dimension_and_fix(self):
        found = analyze_code("x.py", "tempfile.mktemp(t)\n")
        assert found[0].dimension == "permissions"
        assert "mkstemp" in found[0].fix
