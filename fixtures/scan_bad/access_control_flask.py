"""Deliberately missing auth: one guarded route, one bare route.

The project demonstrably uses auth (``@login_required``), so the naked
``/admin/reset`` handler is a genuine access-control debt.
"""

from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/health")
@login_required
def health():
    return "ok"


@app.route("/admin/reset")
def admin_reset():
    # BUG: no auth decorator, even though sibling routes are guarded.
    return "reset done"
