"""XSS-safe patterns — must produce zero findings."""

import html
import json

from flask import Flask, render_template

app = Flask(__name__)


def render_profile(name: str):
    # Autoescaped template rendering; user data is never wrapped in Markup.
    return render_template("profile.html", username=name)


def escape_user_text(user_text: str) -> str:
    return html.escape(user_text)


def dump_config(config: dict):
    # JSON output, not injected into HTML.
    return json.dumps(config)
