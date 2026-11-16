"""Missing auth on routes (Flask/FastAPI/Django + Express).

Heuristic AST analysis: if a project has any auth-related middleware/decorators
and also exposes route handlers without auth, flag the handler.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..models import Evidence

AUTH_INDICATORS = {
    "py": ["login_required", "auth_required", "require_auth", "permission_required",
           "authorization", "auth.login", "jwt_required", "token_required", "login_required",
           "oauth", "authenticate", "user.is_authenticated", "check_permission", "role_required"],
    "js": ["auth", "authMiddleware", "requireAuth", "withAuth", "isAuthenticated",
           "passport", "jwt", "csrf", "authorize", "checkAuth", "middleware"],
}

ROUTE_DECORATOR = re.compile(r"@(?:app\.|bp\.|router\.)?(route|get|post|put|delete|patch)")
# ``use`` is deliberately excluded: ``app.use(express.json())`` middleware
# mounts (body parsers, logging, CORS) are not routes and would be a noisy FP.
EXPRESS_ROUTE = re.compile(r"\bapp\.(get|post|put|delete|patch)\s*\(")
FASTAPI_ROUTE = re.compile(r"@(?:app|router)\.(get|post|put|delete|patch)")


def _new_evidence(file: str, line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
    return Evidence(rule_id=rule_id, title=title, severity="high", file=file, line=line,
                    message=msg, fix=fix, dimension="access_control")


def analyze_project(files: Dict[str, List[Tuple[int, str]]],
                    findings_out: List[Evidence]) -> None:
    """files: {rel_path: [(lineno, text), ...]} for all code files.

    Runs project-wide because auth detection is project-level.
    """
    has_any_auth = False
    # project has any file that references an auth token/decorator
    for path, lines in files.items():
        for _, text in lines:
            low = text.lower()
            if any(an.lower() in low for an in AUTH_INDICATORS["py"]) or \
               any(an.lower() in low for an in AUTH_INDICATORS["js"]):
                has_any_auth = True
                break
        if has_any_auth:
            break

    # Only flag if the project otherwise demonstrates auth being a concern;
    # otherwise a tiny script with no auth at all is normal (avoid FP).
    if not has_any_auth:
        return

    _flag_python(files, findings_out)
    _flag_js(files, findings_out)


_AUTH_DECORATORS = ("login_required", "jwt_required", "auth_required",
                   "require_auth", "token_required", "permission_required",
                   "role_required", "admin_required")


def _flag_python(files, out) -> None:
    for path, lines in files.items():
        if not path.endswith(".py"):
            continue
        for i, (lineno, text) in enumerate(lines):
            s = text.strip()
            if not ROUTE_DECORATOR.search(text):
                continue
            # A route decorator is one line of a contiguous `@`-decorator block
            # above a function definition. Gather the whole block (lines before
            # AND after the route line) and look for any explicit auth
            # decorator -- e.g. `@app.route(x)` then `@login_required` is
            # exactly how a secured handler is written.
            lo = hi = i
            while lo - 1 >= 0 and lines[lo - 1][1].strip().startswith("@"):
                lo -= 1
            while hi + 1 < len(lines) and lines[hi + 1][1].strip().startswith("@"):
                hi += 1
            block = "".join(lines[k][1] for k in range(lo, hi + 1))
            auth_present = any(
                re.search(rf"@{d}\b", block, re.I) for d in _AUTH_DECORATORS
            )
            if auth_present:
                continue
            out.append(_new_evidence(
                path, lineno, "access_control.missing_auth", "路由缺少鉴权",
                f"路由处理器缺少登录/鉴权装饰器 (文件内的其他请求已使用鉴权)，"
                f"所在装饰器块：{block.strip()}",
                "添加 @login_required / @jwt_required 装饰器"))


def _flag_js(files, out) -> None:
    for path, lines in files.items():
        if not (path.endswith(".js") or path.endswith(".ts") or path.endswith(".tsx")):
            continue
        for lineno, text in lines:
            if not EXPRESS_ROUTE.search(text) and not FASTAPI_ROUTE.search(text):
                continue
            # look at the same line for auth-ish chaining
            if any(an in text for an in ["authMiddleware", "requireAuth", "passport.authenticate",
                                          "isAuthenticated", "jwt", "verifyToken", "authorize"]):
                continue
            # check next few lines for middleware in the handler body
            out.append(_new_evidence(
                path, lineno, "access_control.missing_auth", "路由缺少鉴权",
                "Express/Fastify 路由未附加任何鉴权中间件", "在路由上加装 requireAuth 中间件"))
