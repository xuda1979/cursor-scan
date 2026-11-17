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

    def test_call_result_receiver_outer_html_flags(self):
        # The receiver is a function call result; the closing `)` sits before
        # the `.outerHTML` — a word boundary would have missed this.
        found = _analyze("document.getElementById('t').outerHTML = html;\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_call_result_receiver_inner_html_flags(self):
        found = _analyze("queryCard().innerHTML = html;\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_call_chain_receiver_insert_adjacent_html_flags(self):
        found = _analyze(
            "document.querySelector('#rows').insertAdjacentHTML('beforeend', html);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_indexed_receiver_inner_html_flags(self):
        # `]` is non-word too — `sections[0].innerHTML = html` must fire.
        found = _analyze("sections[0].innerHTML = html;\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_call_result_receiver_read_is_quiet(self):
        # Reading the property back from a call result is still a read.
        assert _analyze("const h = getEl('t').outerHTML;\n") == []

    def test_call_result_receiver_plus_read_is_quiet(self):
        assert _analyze("const s = getEl('t').innerHTML + b;\n") == []

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


class TestExecCommand:
    """execCommand('insertHTML', ...) parses its payload as raw HTML into the
    DOM (an OWASP DOM-XSS sink, sibling of insertAdjacentHTML). Only the
    insertHTML command carries an HTML payload; a dynamic payload flags while
    hardcoded literals and cosmetic commands stay quiet."""

    def test_document_insert_html_flags(self):
        found = _analyze("document.execCommand('insertHTML', false, html);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_case_variant_command_flags(self):
        found = _analyze("document.execCommand('insertHtml', true, userHtml);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_any_receiver_flags(self):
        # The sink is the command, not the receiver: text ranges and content
        # editable elements insert HTML through the same execCommand path.
        found = _analyze("range.execCommand('InsertHTML', false, payload);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_concatenation_payload_flags(self):
        found = _analyze(
            "document.execCommand('insertHTML', false, '<b>' + name + '</b>');\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_interpolated_template_payload_flags(self):
        found = _analyze(
            "document.execCommand('insertHTML', false, `<div>${x}</div>`);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_call_result_payload_flags(self):
        found = _analyze("document.execCommand('insertHTML', false, renderCard());\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_static_literal_payload_is_quiet(self):
        # A hardcoded chunk is inert static content.
        assert _analyze("document.execCommand('insertHTML', false, '<b>static</b>');\n") == []

    def test_command_without_payload_is_quiet(self):
        # The one-argument form has nothing to parse into the DOM.
        assert _analyze("document.execCommand('insertHTML');\n") == []

    def test_cosmetic_commands_are_quiet(self):
        # Non-insertHTML commands do not carry an HTML payload.
        assert _analyze("document.execCommand('bold');\n") == []
        assert _analyze("document.execCommand('copy');\n") == []
        assert _analyze("document.execCommand('selectAll', false, 'x');\n") == []

    def test_finding_carries_metadata(self):
        found = _analyze("document.execCommand('insertHTML', false, userHtml);\n")
        assert len(found) == 1
        f = found[0]
        assert f.dimension == "xss"
        assert f.severity == "medium"
        assert f.message and f.fix


class TestContextualFragment:
    """Range.createContextualFragment(html) parses its argument into DOM
    nodes -- a Range-based HTML-parsing sink (sibling of insertAdjacentHTML,
    OWASP DOM-XSS). A dynamic argument flags; hardcoded literals stay inert."""

    def test_range_create_contextual_fragment_flags(self):
        found = _analyze("range.createContextualFragment(userHtml);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_any_receiver_flags(self):
        # The sink is the method itself, not the Range it is called on.
        found = _analyze("selectedRange.createContextualFragment(payload);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_call_result_argument_flags(self):
        found = _analyze("range.createContextualFragment(buildCard(user));\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_concatenation_argument_flags(self):
        found = _analyze("range.createContextualFragment('<p>' + msg + '</p>');\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_interpolated_template_argument_flags(self):
        found = _analyze("range.createContextualFragment(`<li>${name}</li>`);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_identifier_variable_argument_flags(self):
        # A bare variable may hold attacker-controlled HTML markup.
        found = _analyze("range.createContextualFragment(markup);\n")
        assert [f.rule_id for f in found] == ["xss.dom_manipulation"]

    def test_static_literal_argument_is_quiet(self):
        # A hardcoded chunk is inert static content.
        assert _analyze("range.createContextualFragment('<b>static</b>');\n") == []

    def test_double_quoted_static_is_quiet(self):
        assert _analyze("range.createContextualFragment(\"<p>static</p>\");\n") == []

    def test_no_argument_is_quiet(self):
        assert _analyze("range.createContextualFragment();\n") == []

    def test_unrelated_range_method_is_quiet(self):
        # Non-HTML-parsing Range methods carry no markup parsing surface.
        assert _analyze("range.setStart(anchor, 0);\n") == []
        assert _analyze("range.cloneContents();\n") == []

    def test_finding_carries_metadata(self):
        found = _analyze("range.createContextualFragment(userHtml);\n")
        assert len(found) == 1
        f = found[0]
        assert f.dimension == "xss"
        assert f.severity == "medium"
        assert f.message and f.fix


class TestJQueryInsertFamily:
    """jQuery HTML-insertion methods beyond .html(): .append/.prepend/.after/
    .before/.replaceWith (shared names that are text-safe on plain DOM nodes,
    gated on a $/jQuery receiver) and the jQuery-only .wrap family."""

    def test_jquery_append_flags(self):
        assert [f.rule_id for f in _analyze("$('#banner').append(userHtml);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_prepend_flags(self):
        assert [f.rule_id for f in _analyze("$('#menu').prepend(html);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_after_flags(self):
        assert [f.rule_id for f in _analyze("$('li').after(markup);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_before_flags(self):
        assert [f.rule_id for f in _analyze("$('li').before(markup);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_replace_with_flags(self):
        assert [f.rule_id for f in _analyze("jQuery('#rows .row').replaceWith(html);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_wrap_flags(self):
        assert [f.rule_id for f in _analyze("$('article').wrap('<div>' + html + '</div>');\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_wrap_all_flags(self):
        assert [f.rule_id for f in _analyze("$('section').wrapAll(userMarkup);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_wrap_inner_flags(self):
        assert [f.rule_id for f in _analyze("$('.card').wrapInner(markup);\n")] == \
            ["xss.dom_manipulation"]

    def test_jquery_insert_finding_is_medium(self):
        found = _analyze("$('#box').append(userHtml);\n")
        assert len(found) == 1 and found[0].severity == "medium"

    def test_vanilla_dom_append_is_quiet(self):
        # Element.append() inserts nodes/text without parsing HTML; safe.
        assert _analyze("list.append(item);\n") == []

    def test_vanilla_dom_prepend_is_quiet(self):
        assert _analyze("list.prepend(item);\n") == []

    def test_vanilla_dom_replace_with_is_quiet(self):
        assert _analyze("el.replaceWith(newnode);\n") == []

    def test_jquery_text_is_quiet(self):
        # .text() sets escaped text; the safe counterpart of these inserters.
        assert _analyze("$('#banner').text(userInput);\n") == []

    def test_jquery_append_with_literal_is_quiet(self):
        # A hardcoded HTML chunk is inert static content.
        assert _analyze("$('#box').append('<p>static note</p>');\n") == []


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


class TestGetScript:
    """jQuery's $.getScript / jQuery.getScript fetch a remote script and
    evaluate it. A dynamic URL is attacker-influenceable remote code; a
    hardcoded literal is an ordinary static include."""

    def test_dollar_get_script_dynamic_flags(self):
        found = _analyze("$.getScript(url);\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_dollar_get_script_concat_flags(self):
        found = _analyze('$.getScript("https://cdn.example/lib-" + version + ".js");\n')
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_jquery_get_script_dynamic_flags(self):
        found = _analyze("jQuery.getScript(buildUrl());\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_get_script_static_url_is_quiet(self):
        # A hardcoded CDN literal is inert static content.
        assert _analyze('$.getScript("https://cdn.example.com/plugin.js");\n') == []

    def test_get_script_template_literal_dynamic_flags(self):
        found = _analyze("$.getScript(`https://cdn.example.com/lib-${version}.js`);\n")
        assert [f.rule_id for f in found] == ["xss.script_src_injection"]

    def test_get_script_finding_is_medium(self):
        found = _analyze("$.getScript(url);\n")
        assert len(found) == 1 and found[0].severity == "medium"
        assert found[0].dimension == "xss"
        assert found[0].fix


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


class TestOnPropertyAssign:
    """String-form inline event property assignment (``el.onclick = '...'``)
    builds the handler code from a string, the property twin of the
    setAttribute delegation form. A function-reference assignment
    (``el.onclick = onClick``) is the safe idiom and stays quiet; a static
    string literal is inert fixed behavior."""

    def test_quote_concat_assignment_flags(self):
        found = _analyze("el.onclick = 'go(' + url + ')'\n")
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_double_quote_dynamic_flags(self):
        found = _analyze('el.onmouseover = "evil(" + data + ")"\n')
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_interpolated_template_flags(self):
        found = _analyze("el.onclick = `run(${cmd})`\n")
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_any_handler_name_flags(self):
        found = _analyze("img.onerror = 'report(' + location + ')'\n")
        assert [f.rule_id for f in found] == ["xss.event_handler_attr"]

    def test_function_reference_assignment_is_quiet(self):
        # The safe idiom: assign a function, never a code string.
        assert _analyze("el.onclick = onClick\n") == []
        assert _analyze("el.onload = handler\n") == []
        assert _analyze("el.onclick = () => go(nextUrl)\n") == []

    def test_static_literal_assignment_is_quiet(self):
        # A hardcoded handler string is inert fixed behavior.
        assert _analyze("el.onclick = 'alert(1)'\n") == []
        assert _analyze('el.onclick = "doWork()"\n') == []

    def test_tag_or_attribute_not_matching(self):
        # Only el.on<handler> = ... property assignments reach the gate.
        assert _analyze("<div onclick='return doIt()'>\n") == []

    def test_finding_carries_metadata(self):
        found = _analyze("el.onclick = 'go(' + url + ')'\n")
        assert len(found) == 1
        f = found[0]
        assert f.dimension == "xss"
        assert f.rule_id == "xss.event_handler_attr"
        assert f.message and f.fix


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


class TestBypassTrust:
    """Angular's bypassSecurityTrust* / bypassSanitizationTrust* skip the
    built-in sanitizer. A dynamic argument is a documented high-severity XSS
    sink; a plain static literal is inert server-controlled content."""

    def test_dynamic_html_flags(self):
        found = xss.analyze_code("t.ts",
                                 "this.sanitizer.bypassSecurityTrustHtml(html);\n")
        assert [f.rule_id for f in found] == ["xss.bypass_trust"]
        assert found[0].severity == "high"

    def test_dynamic_resource_url_flags(self):
        found = xss.analyze_code("t.ts",
                                 "return this.sanitizer.bypassSecurityTrustResourceUrl(url);\n")
        assert [f.rule_id for f in found] == ["xss.bypass_trust"]

    def test_sanitization_rename_flags(self):
        # Angular >= 15 renamed bypassSecurityTrust* to bypassSanitizationTrust*.
        found = xss.analyze_code("t.ts",
                                 "this.sanitizer.bypassSanitizationTrustStyle(theme.colors);\n")
        assert [f.rule_id for f in found] == ["xss.bypass_trust"]

    def test_concat_argument_flags(self):
        found = xss.analyze_code("t.ts",
                                 'this.sanitizer.bypassSecurityTrustHtml("<b>" + name + "</b>");\n')
        assert [f.rule_id for f in found] == ["xss.bypass_trust"]

    def test_interpolated_template_literal_flags(self):
        found = xss.analyze_code("t.ts",
                                 'this.sanitizer.bypassSecurityTrustHtml(`<b>${x}</b>`);\n')
        assert [f.rule_id for f in found] == ["xss.bypass_trust"]

    def test_static_literal_is_quiet(self):
        assert xss.analyze_code("t.ts",
                                'this.sanitizer.bypassSecurityTrustHtml("<b>done</b>");\n') == []

    def test_static_single_quoted_embedded_quotes_is_quiet(self):
        # HTML strings frequently embed the opposite quote kind; still static.
        assert xss.analyze_code("t.ts",
                                "this.sanitizer.bypassSecurityTrustHtml('<p class=\"muted\">by app</p>');\n") == []

    def test_static_template_literal_is_quiet(self):
        assert xss.analyze_code("t.ts",
                                'this.sanitizer.bypassSecurityTrustHtml(`<b>hi</b>`);\n') == []

    def test_method_reference_is_quiet(self):
        # Taking the method reference without calling it is not a sink
        # (matches the el.onload = fn function-reference philosophy).
        assert xss.analyze_code("t.ts",
                                "const s = this.sanitizer.bypassSecurityTrustHtml;\n") == []

    def test_import_lines_skipped(self):
        assert xss.analyze_code("t.ts",
                                "import { DomSanitizer } from '@angular/platform-browser';\n") == []

    def test_finding_carries_dimension_and_fix(self):
        found = xss.analyze_code("t.ts",
                                 "el.innerHTML = this.sanitizer.bypassSecurityTrustHtml(userHtml);\n")
        ids = [f.rule_id for f in found]
        assert "xss.bypass_trust" in ids  # dom_manipulation also legitimately fires
        bt = next(f for f in found if f.rule_id == "xss.bypass_trust")
        assert bt.dimension == "xss"
        assert bt.fix
