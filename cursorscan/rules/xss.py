"""Cross-site scripting rules: DOM sinks, React's dangerouslySetInnerHTML,
document.write, and Python template-string / Markup rendering.

DOM-based XSS (OWASP) when attacker-controlled input reaches an HTML sink
without escaping. The regex approach flags the sinks themselves; a finding
documents where user data must be escaped or routed through a safe API.

Regex-based fallback; runs on every text file.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

# Property assignments / calls that write raw HTML into the DOM.  jQuery's
# ``.html(arg)`` is an innerHTML setter and a documented DOM-XSS sink, so it
# belongs here too; the empty-argument ``.html()`` getter form (a read) and
# ``.innerHTML`` reads are left alone.
RE_DOM_SINK = re.compile(
    r"\b\.(?:innerHTML|insertAdjacentHTML|outerHTML)\b\s*[=(.]"
    r"|\.html\s*\(\s*[^)]",
    re.I,
)
# React template: dangerouslySetInnerHTML={{ __html: ... }}
RE_DANGEROUS_REACT = re.compile(
    r"\bdangerouslySetInnerHTML\b",
    re.I,
)
# Synchronous document.write / writeln writing anything but a single literal.
RE_DOCUMENT_WRITE = re.compile(
    r"""\bdocument\.write(?:ln)?\s*\(\s*(?!["'`](?:[^"'`\\]|\\.)*["'`]\s*\))""",
    re.I,
)
# ... or a backtick template literal with interpolation (${...}).
RE_DOC_TEMPLATE_INTERP = re.compile(
    r"""\bdocument\.write(?:ln)?\s*\(\s*`[^`]*\$\{""",
)

# Python templating: render_template_string / Markup / format_html
RE_TEMPLATE_RENDER = re.compile(
    r"\b(render_template_string|flask\.Markup|markupsafe\.Markup|\bMarkup)\s*\(",
)
# jinja autoescape disabled: {% autoescape false %} / |safe filter
RE_AUTOESCAPE_OFF = re.compile(
    r"(\{%\s*autoescape\s+(false|off)\s*%\}|\|\s*safe\b)",
)

# Navigating to a dynamic URL: ``location.href = x``, ``location.assign(x)``,
# ``location.replace(x)``. A static-literal target is ordinary navigation; a
# variable / concatenated / interpolated target is an open-redirect candidate
# when the URL is attacker-influenced (CWE-601).
RE_LOCATION_NAV = re.compile(
    r"\blocation\.(?:href\s*=|assign\s*\(|replace\s*\()", re.I,
)
# A right-hand side that is provably static: a plain string literal, or a
# template literal with no interpolation.
_STATIC_RHS = re.compile(
    r"""^["'][^"'+\n]*["']\s*[;)]?$"""          # "static" / 'static'
    r"""|^`(?:[^`$]|\$(?!\{))*`\s*[;)]?$""",    # `static` (no ${...})
    re.VERBOSE,
)
# window.open(...) creates a new browsing context (default target _blank).
# Unless noopener / noreferrer are requested the opened page can control the
# opener: reverse tabnabbing (CWE-1022).
RE_WINDOW_OPEN = re.compile(r"\bwindow\.open\s*\(", re.I)
RE_SINGLE_ARG_CALL = re.compile(r"^\s*[^,)]*\)")

# Python server-side redirect helpers: Flask redirect(), starlette
# RedirectResponse, Django HttpResponseRedirect. A dynamic target is an
# open-redirect candidate (CWE-601); plain string literals and route builders
# (url_for / reverse) stay safe internal targets. ``(?<!\.)`` excludes method
# calls like ``response.redirect(...)``.
RE_REDIRECT = re.compile(
    r"(?<!\.)\b(?:redirect|RedirectResponse|HttpResponseRedirect)\s*\(",
)
_STATIC_REDIRECT_ARG = re.compile(
    r"""^["'][^"'+\n]*["')\s]*$"""      # "static" / 'static'
    r"""|^url_for\s*\("""              # url_for('route') -> internal URL
    r"""|^(?:django[\w.]*\.)?reverse\s*\(""",  # reverse('route') -> internal URL
    re.VERBOSE,
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str,
            severity: str = "medium") -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity=severity,
                        file=source_path, line=line, message=msg, fix=fix,
                        dimension="xss")

    for lineno, raw in code_lines(code):
        if "import " in raw or "from " in raw:
            continue
        line = raw
        if RE_DOM_SINK.search(line):
            findings.append(hit(lineno, "xss.dom_manipulation", "DOM HTML 注入",
                                "innerHTML/outerHTML/insertAdjacentHTML 写入未转义 HTML，"
                                "用户输入可触发 XSS",
                                "改用 textContent / innerText，或先做 HTML 转义"))
        if RE_DANGEROUS_REACT.search(line):
            findings.append(hit(lineno, "xss.dangerous_react", "React 危险 HTML",
                                "dangerouslySetInnerHTML 直接渲染原始 HTML",
                                "使用 React 子节点或先转义 __html 内容"))
        if RE_DOCUMENT_WRITE.search(line) or RE_DOC_TEMPLATE_INTERP.search(line):
            findings.append(hit(lineno, "xss.document_write", "document.write",
                                "document.write 写入非字面量内容",
                                "改用 DOM API (textContent / createElement)"))
        if RE_TEMPLATE_RENDER.search(line):
            findings.append(hit(lineno, "xss.template_render", "模板渲染未转义",
                                "render_template_string / Markup 未转义地渲染用户输入",
                                "启用自动转义并使用 render_template，避免 Markup 包裹用户输入",
                                severity="high"))
        if RE_AUTOESCAPE_OFF.search(line):
            findings.append(hit(lineno, "xss.template_render", "关闭模板转义",
                                "Jinja 自动转义被关闭或将变量标记为 safe",
                                "保持 autoescape 开启，移除 |safe 过滤器"))
        # location navigation sinks: flag dynamic targets, skip static literals
        if RE_LOCATION_NAV.search(line):
            rhs = line.split("=", 1)[1] if "=" in line else line
            if not _STATIC_RHS.search(rhs.strip()):
                findings.append(hit(lineno, "xss.open_redirect", "开放重定向",
                                    "location 跳转到动态 URL，用户可控时可用于钓鱼/开放重定向",
                                    "服务端校验跳转目标为站内白名单域名"))
        # window.open(...) without noopener: reverse tabnabbing.
        # Only the two-argument target + features form is dangerous; the
        # one-argument window.open(url) call is a plain navigation.
        if RE_WINDOW_OPEN.search(line):
            args = RE_WINDOW_OPEN.sub("", line, count=1)
            if args.count(",") >= 1 and "noopener" not in line.lower() \
                    and "noreferrer" not in line.lower():
                findings.append(hit(lineno, "xss.reverse_tabnabbing", "反向标签窃取",
                                    "window.open 未指定 noopener，新页面可控制原页面",
                                    "追加 ', noopener' 或 'noopener,noreferrer' 特性"))
        # Python server-side open redirect: flag dynamic targets, skip static
        # literals and internal route builders.
        if RE_REDIRECT.search(line):
            arg = line.split("(", 1)[1] if "(" in line else ""
            if not _STATIC_REDIRECT_ARG.search(arg.strip()):
                findings.append(hit(lineno, "xss.open_redirect", "开放重定向",
                                    "redirect 到动态 URL，用户输入可被用于钓鱼/开放重定向",
                                    "校验跳转目标为站内白名单，拒绝外部 scheme"))
    return findings
