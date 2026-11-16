"""Deliberately unsafe XSS patterns: template rendering and Markup."""

from flask import Flask, Markup, render_template_string, request

app = Flask(__name__)


def render_user_panel(name: str):
    html = render_template_string("<h1>Welcome " + name + "</h1>")
    return html


def mark_richtext(user_text: str):
    return Markup(user_text)


def announce_winner(username: str):
    badge = "<b>winner:</b> " + username
    return mark_safe(badge)


def safe_filter_bad(user: str):
    template = "{{ user | safe }}"
    return render_template_string(template, user=user)
