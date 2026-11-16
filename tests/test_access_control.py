"""Tests for the access_control dimension: missing-auth route detection.

The rule only fires when a project demonstrably uses auth elsewhere (a flask
route guarded by ``@login_required`` vs. a sibling bare route, or an express
app that imports JWT/passport but exposes a middleware-free handler), so it
stays quiet on small scripts that have no auth at all -- that would be noise,
not a debt.
"""

from __future__ import annotations

from cursorscan.rules import access_control
from cursorscan.rules.access_control import _AUTH_DECORATORS


class TestPythonFlagging:
    def test_unsecured_route_next_to_secured_one(self):
        files = {
            "app.py": [
                (1, "from flask import Flask"),
                (2, "app = Flask(__name__)"),
                (3, "@app.route('/secure')"),
                (4, "@login_required"),
                (5, "def secure_page():"),
                (6, "    return 'ok'"),
                (7, "@app.route('/admin')"),
                (8, "def admin_panel():"),
                (9, "    return 'admin'"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert [(f.rule_id, f.line) for f in out] == \
            [("access_control.missing_auth", 7)]
        f = out[0]
        assert f.dimension == "access_control"
        assert f.severity == "high"
        assert "login_required" in f.fix

    def test_auth_decorator_above_route_is_secure(self):
        files = {
            "app.py": [
                (1, "from flask import Flask"),
                (2, "app = Flask(__name__)"),
                (3, "@jwt_required"),
                (4, "@app.route('/a')"),
                (5, "def a():"),
                (6, "    return 'a'"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert out == []

    def test_all_routes_secured_produce_nothing(self):
        files = {
            "app.py": [
                (1, "@app.route('/a')"),
                (2, "@login_required"),
                (3, "def a():"),
                (4, "@app.route('/b')"),
                (5, "@require_auth"),
                (6, "def b():"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert out == []

    def test_bp_and_http_verb_decorators_match(self):
        files = {
            "views.py": [
                (1, "from flask import Blueprint"),
                (2, "bp = Blueprint('x', __name__)"),
                (3, "@bp.post('/scan')"),
                (4, "def scan():"),
                (5, "@bp.get('/health')"),
                (6, "@login_required"),
                (7, "def health():"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert [(f.rule_id, f.line) for f in out] == \
            [("access_control.missing_auth", 3)]


class TestAuthIndicators:
    def test_known_auth_decorators_are_recognized(self):
        assert _AUTH_DECORATORS  # non-empty table

    def test_priority_decorator_not_mistaken_for_auth(self):
        # "@app.route" must not look like an auth decorator itself.
        for token in _AUTH_DECORATORS:
            assert "app.route" != token


class TestJavascriptFlagging:
    def test_express_route_without_auth_middleware(self):
        files = {
            "server.ts": [
                (1, "import jwt from 'jsonwebtoken'"),
                (2, "import express from 'express'"),
                (3, "const app = express()"),
                (4, "app.use(authMiddleware)"),
                (5, "app.post('/transfer', (req, res) => {"),
                (6, "  res.send('ok')"),
                (7, "})"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        # authMiddleware on line 4 /\ is still not the /transfer handler.
        assert [(f.rule_id, f.line) for f in out] == \
            [("access_control.missing_auth", 5)]

    def test_route_with_auth_same_line_is_quiet(self):
        files = {
            "server.ts": [
                (1, "import passport from 'passport'"),
                (2, "const app = express()"),
                (3, "app.get('/me', passport.authenticate('jwt'))"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert out == []

    def test_middleware_mount_is_not_a_route(self):
        # app.use(...) mounts body parsers / logging / CORS — those are not
        # routes and must not be flagged as unauthenticated handlers.
        files = {
            "server.js": [
                (1, "const express = require('express')"),
                (2, "const app = express()"),
                (3, "app.use(express.json())"),
                (4, "app.use(cors())"),
                (5, "app.get('/secure', requireAuth, (req, res) => {"),
                (6, "  res.send('ok')"),
                (7, "})"),
            ],
        }
        out = []
        access_control.analyze_project(files, out)
        assert out == []


class TestNoAuthContext:
    def test_project_without_any_auth_stays_quiet(self):
        files = {"app.py": [(1, "from flask import Flask"),
                            (2, "app = Flask(__name__)"),
                            (3, "@app.route('/')"),
                            (4, "def home():"),
                            (5, "    return 'hi'")]}
        out = []
        access_control.analyze_project(files, out)
        assert out == []

    def test_no_route_files_at_all(self):
        out = []
        access_control.analyze_project({"util.py": [(1, "def f(): pass")]}, out)
        assert out == []


class TestPipelineIntegration:
    def test_scan_project_detects_missing_auth(self, tmp_path):
        from cursorscan.scan import scan_project
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/secure')\n"
            "@login_required\n"
            "def secure():\n"
            "    return 'ok'\n"
            "@app.route('/open')\n"
            "def open_route():\n"
            "    return 'world'\n",
            encoding="utf-8")
        result = scan_project(str(tmp_path))
        ids = {f.rule_id for f in result.findings}
        assert "access_control.missing_auth" in ids
        assert "access_control" in result.dimensions

    def test_clean_fixture_has_no_access_findings(self, scan_good_dir):
        from cursorscan.scan import scan_project
        result = scan_project(scan_good_dir)
        assert not any(f.dimension == "access_control"
                       for f in result.findings)
