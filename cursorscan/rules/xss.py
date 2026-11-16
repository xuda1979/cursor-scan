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
# ``.innerHTML`` reads are left alone.  Compound ``+=`` writes are sinks as
# well; a bare ``+`` (``a.innerHTML + b`` is a read) stays quiet.
RE_DOM_SINK = re.compile(
    r"\b\.(?:innerHTML|insertAdjacentHTML|outerHTML)\b\s*(?:\+=|[=(.])"
    r"|\.html\s*\(\s*[^)]",
    re.I,
)
# jQuery's HTML-insertion family beyond .html(): .append / .prepend /
# .after / .before / .replaceWith parse their argument as raw HTML exactly
# like innerHTML, and .wrap / .wrapAll / .wrapInner take an HTML string to
# build the wrapper. The wrap family is jQuery-only and matches directly;
# the names shared with the DOM (append/prepend/after/before/replaceWith,
# which are text-safe node insertions on plain elements) only match through
# a $(...)/jQuery(...) selection, i.e. the jQuery API surface. The argument
# is captured so a hardcoded string-literal stays quiet (inert static
# content); any dynamic value is attacker-influenceable.
RE_JQUERY_INSERT = re.compile(
    r"""\$\(\s*[^)]*\)\.(?:append|prepend|after|before|replaceWith)\s*\(\s*([^)]*)"""
    r"""|jQuery\(\s*[^)]*\)\.(?:append|prepend|after|before|replaceWith)\s*\(\s*([^)]*)"""
    r"""|\.(?:wrap|wrapAll|wrapInner)\s*\(\s*([^)]*)""",
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
    r"""\b(?:window\.)?(?:document\.)?location\.(?:href\s*\+?=|assign\s*\(|replace\s*\()"""
    r"""|(?:window\.)?document\.location\s*\+?="""   # document.location = url navigates
    r"""|window\.location\s*\+?=""",                  # window.location = url navigates
    re.I,
)
# A right-hand side that is provably static: a plain string literal, or a
# template literal with no interpolation.  Each quoted form allows embedded
# quotes of the *opposite* kind (TS/JS HTML strings like
# ``'<p class="x">...</p>'`` are still static content); concatenation and
# interpolation both fail the trailing ``[;)]?$`` anchor.
_STATIC_RHS = re.compile(
    r"""^(?:'[^'\n]*'|"[^"\n]*")[;)]?$"""       # "static" / 'static'
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

# Django's mark_safe() is the server-side counterpart of a raw-HTML sink:
# content passed through it bypasses autoescaping. A plain string literal is
# static (server-controlled) content, but wrapping a variable, a formatted
# string, or a concatenation marks user-influenced data as safe.
RE_MARK_SAFE = re.compile(r"(?<!\.)\bmark_safe\s*\(")
# A literal is static (server-controlled) content even with r/b/rb/br
# prefixes; an f-string is only static when it carries no interpolation
# (no ``{...}``), otherwise the wrapped value depends on runtime data.
_STATIC_WRAP_ARG = re.compile(
    r"""^(?:[rb][rb]?)?["'][^"'\n]*["')\s]*$"""     # plain / r / b / rb literal
    r"""|^(?:f)["'][^"'\n{]*["')\s]*$""",           # f-string without {..}
    re.I | re.VERBOSE,
)

# ``scheme:`` URLs that execute script when reached through a navigation or
# scriptable element: javascript:, vbscript:, and data:text/html.  The match
# stays broad; the analysis branch keeps static literals ("javascript:void(0)"
# is inert inline code) and pure validation lines (indexOf / startsWith / ==
# comparisons) quiet, so only concatenated or dynamically built values flag.
RE_SCRIPT_SCHEME_URL = re.compile(
    r"""\b(?:javascript|vbscript)\s*:"""
    r"""|data:text/html\b""",
    re.I,
)
# Validation / comparison contexts test for the scheme instead of navigating
# to it; such lines never reach the dangerous dynamic assignment.
RE_SCHEME_CHECK = re.compile(
    r"""\b(?:indexOf|startsWith|endsWith|includes|match|search)\s*\("""
    r"""|(?:===|!==|==|!=|<=|>=|<>|~=)""",
)

# Script-capable element attributes accepting a raw value: <script src> and
# <iframe src> (script execution / clickjacking-bridge) plus the HTML5
# srcdoc family. A static literal is inert; any non-literal value is
# attacker-influenceable.
RE_SRC_SINK = re.compile(
    r"\b(?:script|iframe|embed|object|frame)\.(?:src|srcdoc)\s*=",
    re.I,
)

# String forms of inline event handlers: el.setAttribute("onclick", code) is
# the scriptable alternative to the el.onclick = fn property assignment.
# Only the string-attribute form (delegation) is flagged; the .onload=fn
# property-assignment idiom is function-reference-based and safe.
RE_SETATTR_EVENT = re.compile(
    r"""\.setAttribute\s*\(\s*["']on[a-z]+\s*["']\s*,""",
    re.I,
)

# Svelte's {@html ...} block inserts raw, unescaped HTML -- the component
# counterpart of innerHTML. Only a non-literal payload is flagged; a hardcoded
# string is inert server-controlled content.
RE_SVELTE_HTML = re.compile(r"""\{@html\s+""")

# Template-framework bindings that write raw HTML into the DOM: Vue's
# ``v-html`` and its ``:innerHTML`` v-bind form, plus Angular's
# ``[innerHTML]`` / ``[outerHTML]`` property bindings. The bound expression
# is captured so a hardcoded string-literal stays quiet (inert static
# content); any dynamic expression is attacker-influenceable.
RE_HTML_BINDING = re.compile(
    r"""\bv-html\s*=\s*["']([^"']+)["']"""
    r"""|\[(?:inner|outer)HTML\]\s*=\s*["']([^"']+)["']"""
    r"""|:innerHTML\s*=\s*["']([^"']+)["']""",
    re.I,
)

# Angular's sanitizer bypasses: the framework counterpart of mark_safe. Using
# them on anything but a static footer is a documented XSS sink; newer Angular
# (>= 15) renames bypassSecurityTrust* to bypassSanitizationTrust*. A plain
# string-literal argument is inert static content.
RE_BYPASS_TRUST = re.compile(
    r"""\.(?:bypassSecurityTrust|bypassSanitizationTrust)\w*\s*\(""",
)


def _static_literal_arg(arg: str) -> bool:
    """True when ``arg`` is a plain string literal or a backtick template
    literal with no interpolation (same shape as _STATIC_RHS)."""
    return bool(_STATIC_RHS.search(arg.strip()))


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
        if m := RE_JQUERY_INSERT.search(line):
            arg = next((g for g in m.groups() if g is not None), "")
            if not _static_literal_arg(arg.strip()):
                findings.append(hit(lineno, "xss.dom_manipulation", "DOM HTML 注入",
                                    "jQuery append/prepend/after/before/replaceWith/wrap* "
                                    "将字符串解析为 HTML，用户输入可触发 XSS",
                                    "改用 jQuery .text() 或 document.createElement，先做 HTML 转义"))
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
        # Django mark_safe(): only a dynamic / built argument is dangerous;
        # wrapping a plain static string is a no-op.
        if RE_MARK_SAFE.search(line):
            arg = line.split("(", 1)[1] if "(" in line else ""
            if not _STATIC_WRAP_ARG.search(arg.strip()):
                findings.append(hit(lineno, "xss.mark_safe", "Django 未转义输出",
                                    "mark_safe 将变量标记为安全 HTML，绕过自动转义",
                                    "渲染前对用户输入做 HTML 转义，或改用普通模板变量",
                                    severity="high"))
        # javascript:/vbscript:/data:text/html script URLs in navigation and
        # src attributes. A static literal is inert (e.g. void(0) links) and
        # scheme checks / comparisons only test the value, so both stay quiet;
        # a concatenated or dynamic value executes script.
        if RE_SCRIPT_SCHEME_URL.search(line):
            rhs = line.split("=", 1)[1] if "=" in line else ""
            if rhs and not RE_SCHEME_CHECK.search(line) \
                    and not _static_literal_arg(rhs):
                findings.append(hit(lineno, "xss.javascript_url", "脚本 URL 注入",
                                    "动态构建的 javascript:/data: URL 会执行脚本",
                                    "拒绝 javascript:/data: scheme，仅允许 http(s)"))
        # Dynamic script/iframe/frame src or srcdoc: attacker-influenceable
        # values can load remote scripts. Static-literal values are inert.
        if RE_SRC_SINK.search(line):
            arg = line.split("=", 1)[1] if "=" in line else ""
            if not _static_literal_arg(arg):
                findings.append(hit(lineno, "xss.script_src_injection", "脚本源注入",
                                    "动态赋值给 script/iframe 的 src 可加载恶意脚本",
                                    "固定允许的静态源，服务端校验 URL 白名单"))
        # String-form inline event handlers via setAttribute("onclick", ...).
        if RE_SETATTR_EVENT.search(line):
            findings.append(hit(lineno, "xss.event_handler_attr", "事件属性注入",
                                "setAttribute 设置字符串形式的内联事件处理器",
                                "使用 addEventListener + 函数引用，或先转义回调内容"))
        # Svelte {@html ...} raw-insertion block (works on .svelte files).
        if RE_SVELTE_HTML.search(line):
            rest = line.split("{@html", 1)[1].split("}", 1)[0].strip()
            if not _static_literal_arg(rest):
                findings.append(hit(lineno, "xss.svelte_html", "Svelte 原始 HTML",
                                    "{@html ...} 直接插入未转义 HTML，用户输入可触发 XSS",
                                    "对内容做 HTML 转义，或改用普通插值 {expr}",
                                    severity="high"))
        # Vue v-html / Angular [innerHTML] / :innerHTML raw-HTML bindings.
        # The bound expression is captured; a hardcoded string-literal is inert
        # static content, any dynamic value is attacker-influenceable.
        if m := RE_HTML_BINDING.search(line):
            payload = (m.group(1) or m.group(2) or m.group(3) or "").strip()
            if not _static_literal_arg(payload):
                findings.append(hit(lineno, "xss.html_binding", "模板绑定原始 HTML",
                                    "v-html / [innerHTML] 绑定将未转义 HTML 写入 DOM，"
                                    "用户输入可触发 XSS",
                                    "对绑定值做 HTML 转义，或使用普通插值 {{ expr }}"))
        # Angular sanitizer bypasses: trustHtml/RSS/style/script/sanitizer
        # mark untrusted data as safe; only a plain static literal is inert.
        if RE_BYPASS_TRUST.search(line):
            arg = line.split("(", 1)[1] if "(" in line else ""
            # TS statements commonly end with a semicolon; drop it and any
            # trailing whitespace so ``("...");`` still reads as a literal.
            arg = arg.strip().rstrip(";")
            if not _static_literal_arg(arg):
                findings.append(hit(lineno, "xss.bypass_trust", "Angular 绕过消毒器",
                                    "bypassSecurityTrust* 将数据标记为安全，绕过 Angular"
                                    "内建 XSS 消毒",
                                    "不使用 bypass API；对用户输入做独立消毒并仅使用"
                                    "内插/属性绑定渲染",
                                    severity="high"))
    return findings
