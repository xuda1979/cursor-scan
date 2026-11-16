"""Tests for the P4 XSS rule dimension (DOM sinks, React, document.write,
template rendering).

Unit tests drive ``xss.analyze_code`` directly against planted snippets, then
end-to-end tests assert the new findings flow into the scan result and stay
off the clean fixture.
"""

from __future__ import annotations

from cursorscan.rules import xss


def _analyze(code: str):
    return xss.analyze_code("/proj/app.py", code)


class TestDomSink:
    def test_inner_html_assignment(self):
        ids = [f.rule_id for f in _analyze("banner.innerHTML = html;\n")]
        assert "xss.dom_manipulation" in ids

    def test_outer_html_assignment(self):
        ids = [f.rule_id for f in _analyze("banner.outerHTML = cardHtml;\n")]
        assert "xss.dom_manipulation" in ids

    def test_insert_adjacent_html_call(self):
        # Method-call form (followed by `(`) must be caught too.
        ids = [f.rule_id for f in _analyze(
            'banner.insertAdjacentHTML("beforeend", html);\n')]
        assert "xss.dom_manipulation" in ids

    def test_safe_text_content_not_flagged(self):
        assert _analyze("banner.textContent = text;\n") == []

    def test_inner_html_read_is_not_a_write(self):
        # Reading the property back must not be treated as a sink.
        assert _analyze("const x = banner.innerHTML;\n") == []

    def test_inner_html_compound_assignment_is_a_write(self):
        # `+=` appends raw HTML; the same DOM-XSS sink as `=`.
        found = _analyze("banner.innerHTML += userHtml;\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_inner_html_plus_read_is_not_a_write(self):
        # A bare `+` reads the current value into a larger expression.
        assert _analyze("const s = a.innerHTML + b;\n") == []

    def test_jquery_html_setter_is_a_sink(self):
        # jQuery's .html() is an innerHTML setter; a DOM-XSS sink.
        found = _analyze("$('#box').html(userInput);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_jquery_html_concat_is_a_sink(self):
        found = _analyze("$('#box').html('<b>' + name + '</b>');\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_jquery_html_getter_is_not_a_sink(self):
        # Reading content back with the no-argument getter form is a read.
        assert _analyze("const content = $('#box').html();\n") == []

    def test_jquery_text_is_not_a_sink(self):
        # .text() escapes; it is the safe counterpart of .html().
        assert _analyze("$('#box').text(userInput);\n") == []

    def test_findings_carry_xss_dimension_and_fix(self):
        found = _analyze("banner.innerHTML = html;\n")
        assert len(found) == 1
        f = found[0]
        assert f.dimension == "xss"
        assert f.severity == "medium"
        assert f.message and f.fix


class TestReact:
    def test_dangerously_set_inner_html(self):
        found = _analyze("props = { dangerouslySetInnerHTML: { __html: html } };\n")
        assert [f.rule_id for f in found] == ["xss.dangerous_react"]

    def test_safe_create_element_not_flagged(self):
        assert _analyze('React.createElement("h1", { title: name }, name);\n') == []


class TestDocumentWrite:
    def test_write_with_variable(self):
        found = _analyze("document.write(value);\n")
        assert [f.rule_id for f in found] == ["xss.document_write"]

    def test_write_with_expression(self):
        found = _analyze('document.write("<b>" + name + "</b>");\n')
        assert [f.rule_id for f in found] == ["xss.document_write"]

    def test_write_literal_is_safe(self):
        assert _analyze('document.write("<p>static footer</p>");\n') == []


class TestOpenRedirect:
    def test_location_href_dynamic_flags(self):
        found = _analyze("location.href = userInput;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_location_href_concat_flags(self):
        found = _analyze("location.href = '/go?next=' + req.query.next;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_location_href_compound_assignment_flags(self):
        # `+=` appends to the current location dynamically.
        found = _analyze("location.href += token;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_location_assign_flags(self):
        found = _analyze("location.assign(redirectUrl);\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_location_replace_flags(self):
        found = _analyze("location.replace(window.location.search);\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_static_target_is_quiet(self):
        assert _analyze('location.href = "/home";\n') == []

    def test_href_read_is_quiet(self):
        assert _analyze("const cur = location.href;\n") == []

    def test_document_location_assignment_flags(self):
        found = _analyze("document.location = userInput;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_window_location_assignment_flags(self):
        found = _analyze("window.location = nextUrl;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_window_location_href_flags(self):
        found = _analyze("window.location.href = nextUrl;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_document_location_compound_assignment_flags(self):
        found = _analyze("document.location += token;\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_document_location_static_is_quiet(self):
        assert _analyze('document.location = "/home";\n') == []

    def test_finding_carries_fix(self):
        found = _analyze("location.assign(redirectUrl);\n")
        assert len(found) == 1
        assert found[0].dimension == "xss"
        assert found[0].fix


class TestReverseTabnabbing:
    def test_two_arg_open_without_noopener_flags(self):
        found = _analyze("window.open(url, '_blank');\n")
        assert [f.rule_id for f in found] == ["xss.reverse_tabnabbing"]

    def test_open_with_noopener_is_quiet(self):
        assert _analyze("window.open(url, '_blank', 'noopener');\n") == []

    def test_open_with_noreferrer_is_quiet(self):
        assert _analyze("window.open(url, '_blank', 'noopener,noreferrer');\n") == []

    def test_single_arg_open_is_plain_navigation(self):
        # window.open(url) without a target opens a new tab but is a plain
        # navigation -- the caller has no reference to control.
        assert _analyze("window.open(url);\n") == []


class TestServerSideOpenRedirect:
    """Python redirect helpers: Flask redirect(), starlette
    RedirectResponse, Django HttpResponseRedirect."""

    def test_flask_redirect_with_request_arg_flags(self):
        found = _analyze('return redirect(request.args.get("next"))\n')
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_starlette_redirect_response_flags(self):
        found = _analyze("return RedirectResponse(req.query_params['url'])\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_django_http_response_redirect_flags(self):
        found = _analyze("return HttpResponseRedirect(request.GET.get('next'))\n")
        assert [f.rule_id for f in found] == ["xss.open_redirect"]

    def test_static_literal_redirect_is_quiet(self):
        assert _analyze('return redirect("/home")\n') == []

    def test_url_for_route_is_quiet(self):
        # url_for builds a same-app URL; a safe internal target.
        assert _analyze("return redirect(url_for('profile'))\n") == []

    def test_django_reverse_route_is_quiet(self):
        assert _analyze("return HttpResponseRedirect(reverse('profile'))\n") == []

    def test_method_call_redirect_is_quiet(self):
        # HTTP-level response.redirect() is not a framework open-redirect helper.
        assert _analyze("response.redirect('/login')\n") == []


class TestPythonTemplates:
    def test_render_template_string(self):
        found = _analyze('html = render_template_string("<h1>" + name + "</h1>")\n')
        ids = [f.rule_id for f in found]
        assert "xss.template_render" in ids
        assert found[0].severity == "high"

    def test_markup_wrapper(self):
        found = _analyze("return Markup(user_text)\n")
        assert [f.rule_id for f in found] == ["xss.template_render"]
        assert found[0].severity == "high"

    def test_import_lines_skipped(self):
        # `from flask import ... Markup` must not self-trigger.
        assert _analyze("from flask import Markup, render_template_string\n") == []

    def test_safe_render_template(self):
        # The autoescaping render_template is fine.
        assert _analyze('return render_template("profile.html", user=name)\n') == []

    def test_autoescape_off(self):
        found = _analyze("template = \"{{ user | safe }}\"\n")
        assert [f.rule_id for f in found] == ["xss.template_render"]
        assert all(f.message for f in found)

    def test_autoescape_block_off(self):
        found = _analyze("{% autoescape false %}\n")
        assert [f.rule_id for f in found] == ["xss.template_render"]

    def test_plain_variable_interpolation_is_safe(self):
        assert _analyze("template = \"Hello {{ username }}\"\n") == []


class TestPipelineIntegration:
    def test_bad_fixture_reports_xss(self, scan_bad_dir):
        from cursorscan.scan import scan_project
        result = scan_project(scan_bad_dir)
        per_file: dict[str, set[str]] = {}
        for f in result.findings:
            if f.dimension != "xss":
                continue
            per_file.setdefault(f.file.rsplit("/", 1)[-1], set()).add(f.rule_id)
        assert "xss.template_render" in per_file.get("xss.py", set())
        assert "xss.mark_safe" in per_file.get("xss.py", set())
        assert {"xss.dom_manipulation", "xss.dangerous_react", "xss.document_write"} <= \
            per_file.get("xss.js", set())
        assert {"xss.script_src_injection", "xss.event_handler_attr"} <= \
            per_file.get("xss.js", set())
        assert "xss" in result.dimensions
        for f in result.findings:
            if f.dimension == "xss":
                assert f.code_snippet, "xss finding needs a backfilled snippet"

    def test_good_fixture_stays_xss_clean(self, scan_good_dir):
        from cursorscan.scan import scan_project
        result = scan_project(scan_good_dir)
class TestMarkSafe:
    """Django mark_safe() wraps user-influenced HTML as trusted; a plain
    literal is server-side static content and stays quiet."""

    def test_dynamic_variable_flags(self):
        found = _analyze("return mark_safe(username)\n")
        assert [f.rule_id for f in found] == ["xss.mark_safe"]
        assert found[0].severity == "high"

    def test_concatenation_flags(self):
        found = _analyze('return mark_safe("<b>winner:</b> " + username)\n')
        assert [f.rule_id for f in found] == ["xss.mark_safe"]

    def test_interpolated_fstring_flags(self):
        found = _analyze('return mark_safe(f"<b>{username}</b>")\n')
        assert [f.rule_id for f in found] == ["xss.mark_safe"]

    def test_static_literal_is_quiet(self):
        assert _analyze('return mark_safe("<b>done</b>")\n') == []

    def test_helper_functions_are_quiet(self):
        # mark_unsafe / my.mark_safe variants are unrelated names or methods.
        assert _analyze("mark_unsafe(x)\n") == []
        assert _analyze("django.utils.mark_safe(x)\n") == []
        assert _analyze("from django.utils.safestring import mark_safe\n") == []


class TestScriptSchemeUrl:
    """javascript:/vbscript:/data: URLs execute script when reached. Static
    literals are inert; validation/comparison lines only test the value."""

    def test_dynamic_concatenation_flags(self):
        found = _analyze('el.href = "javascript:" + code\n')
        assert [f.rule_id for f in found] == ["xss.javascript_url"]

    def test_static_void_literal_is_quiet(self):
        assert _analyze('el.href = "javascript:void(0)"\n') == []

    def test_static_data_url_with_script_is_quiet(self):
        # A hardcoded data:text/html,<script> literal is server-controlled
        # static content (same inert treatment as the void(0) case above).
        assert _analyze('el.href = "data:text/html,<script>alert(1)</script>"\n') == []

    def test_dynamic_built_url_flags(self):
        found = _analyze('el.href = "data:text/html," + payload\n')
        assert "xss.javascript_url" in [f.rule_id for f in found]

    def test_scheme_validator_is_quiet(self):
        assert _analyze('if (url.indexOf("javascript:") >= 0) return;\n') == []
        assert _analyze('if (url.startsWith("javascript:")) return;\n') == []
        assert _analyze('if (a === "javascript:alert(1)") return;\n') == []


class TestScriptSrcInjection:
    """Dynamic script/iframe/embed/object/frame src or srcdoc values can load
    remote code; fixed static literals are inert."""

    def test_dynamic_script_src_flags(self):
        found = _analyze("script.src = userUrl\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_dynamic_iframe_srcdoc_flags(self):
        found = _analyze("frame.srcdoc = payload\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_dynamic_object_src_flags(self):
        found = _analyze("object.src = blobUrl\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_static_script_src_is_quiet(self):
        assert _analyze('script.src = "https://cdn.example/x.js"\n') == []


class TestSetAttrEvent:
    """setAttribute with a string-form on* handler builds code from a string;
    property assignments (el.onload = fn) use function references and are fine."""

    def test_string_onclick_flags(self):
        found = _analyze('el.setAttribute("onclick", code)\n')
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_string_onmouseover_flags(self):
        found = _analyze('el.setAttribute("onmouseover", snippet)\n')
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_property_assignment_is_quiet(self):
        assert _analyze("el.onload = handler\n") == []
        assert _analyze("el.onclick = onClick\n") == []

    def test_data_attribute_is_quiet(self):
        assert _analyze('el.setAttribute("data-id", x)\n') == []
        assert _analyze('el.setAttribute("type", "text")\n') == []

    def test_single_quote_form_flags(self):
        found = _analyze("el.setAttribute('onclick', code)\n")
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]


class TestSvelteHtml:
    """Svelte's {@html ...} inserts raw unescaped HTML. Non-literal payloads
    flag as high; hardcoded strings and plain interpolation stay quiet."""

    def test_dynamic_expression_flags(self):
        found = xss.analyze_code("t.svelte", "<p>{@html userBio}</p>\n")
        assert [f.rule_id for f in found] == ["xss.svelte_html"]
        assert found[0].severity == "high"

    def test_interpolated_fstring_flags(self):
        found = xss.analyze_code("t.svelte", '<p>{@html f"<b>{x}</b>"}</p>\n')
        assert [f.rule_id for f in found] == ["xss.svelte_html"]

    def test_concat_expression_flags(self):
        found = xss.analyze_code("t.svelte", '<p>{@html user + "!"}</p>\n')
        assert [f.rule_id for f in found] == ["xss.svelte_html"]

    def test_static_literal_is_quiet(self):
        assert xss.analyze_code("t.svelte", '<p>{@html "<b>hi</b>"}</p>\n') == []

    def test_plain_interpolation_is_quiet(self):
        assert xss.analyze_code("t.svelte", "<p>{username}</p>\n") == []

    def test_import_lines_skipped(self):
        assert xss.analyze_code("t.svelte", "import { onMount } from 'svelte';\n") == []


class TestHtmlBinding:
    """Vue v-html / Angular [innerHTML] / :innerHTML raw-HTML bindings write
    unescaped HTML into the DOM. Dynamic bound values flag as medium;
    hardcoded string literals and plain interpolation stay quiet."""

    def test_vue_v_html_flags(self):
        found = xss.analyze_code("t.vue", '<div v-html="userBio"></div>\n')
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_vue_v_html_single_quotes_flags(self):
        found = xss.analyze_code("t.vue", "<div v-html='userBio'></div>\n")
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_vue_v_html_bound_to_property_flags(self):
        # A nested property is user-influenceable, just like a plain variable.
        found = xss.analyze_code("t.vue", '<div v-html="article.html"></div>\n')
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_vue_colon_inner_html_flags(self):
        # The ``v-bind`` shorthand form of v-html.
        found = xss.analyze_code("t.vue", '<div :innerHTML="payload"></div>\n')
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_angular_inner_html_flags(self):
        found = xss.analyze_code("t.vue", '<div [innerHTML]="post.body"></div>\n')
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_angular_outer_html_flags(self):
        found = xss.analyze_code("t.vue", '<div [outerHTML]="card.template"></div>\n')
        assert [f.rule_id for f in found] == ["xss.html_binding"]

    def test_tailwind_like_inner_html_text_is_quiet(self):
        # A plain HTML attribute token that merely contains "innerHTML"
        # (not a binder of that name) is not a raw-HTML sink.
        assert xss.analyze_code("t.vue",
                                '<p class="x-innerhtml-helper">hi</p>\n') == []

    def test_static_literal_is_quiet(self):
        # A hardcoded literal is inert server-controlled content.
        found = xss.analyze_code("t.vue", '<div v-html="\'<b>hi</b>\'"></div>\n')
        assert [f.rule_id for f in found] == []

    def test_plain_interpolation_is_quiet(self):
        # {{ expr }} escapes; it is the safe counterpart of v-html.
        assert xss.analyze_code("t.vue", "<p>{{ username }}</p>\n") == []

    def test_finding_carries_fix(self):
        found = xss.analyze_code("t.vue", '<div v-html="userBio"></div>\n')
        assert found[0].dimension == "xss"
        assert found[0].fix
