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

# Property assignments / calls that write raw HTML into the DOM.
RE_DOM_SINK = re.compile(
    r"\b\.(?:innerHTML|insertAdjacentHTML|outerHTML)\b\s*[=(.]",
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
# Jinja autoescape disabled: {% autoescape false %} / |safe filter
RE_AUTOESCAPE_OFF = re.compile(
    r"(\{%\s*autoescape\s+(false|off)\s*%\}|\|\s*safe\b)",
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
    return findings
